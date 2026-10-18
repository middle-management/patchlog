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

// §11.2, §C.5, §E.2.3: sealing an e2e inverse needs the current epoch and
// pad, which a writer limited to some resources learns from /keys, with
// the keys relayed to its enc, without reading the keyring. One whose
// grant carries no enc is 422 there, so it is refused once it learns the
// level from the resource log, with or without an E2E view.
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
	must(x.AppendSealed(ctx, "le", "a", head(t, ac, "le", "a"), ops(op("add", "/m", 1))))

	rules := []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}
	bare := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:admin", []string{"le"}, []string{"read", "append"}, map[string]any{"rules": rules})))
	if _, err := bare.PlanUndo(ctx, "le", g); !errors.Is(err, client.ErrNeedResources) {
		t.Fatalf("without resources: %v", err)
	}
	for _, opts := range [][]client.UndoOption{
		{client.UndoResources("a")},
		{client.UndoResources("a"), client.UndoE2E(bare.E2E(priv))},
	} {
		if _, err := bare.Undo(ctx, "le", g, opts...); !errors.Is(err, client.ErrUndoE2ELimited) {
			t.Fatalf("limited e2e undo without enc: %v", err)
		}
	}
	if h := must(bare.Head(ctx, "le", "a")); h.ID != head(t, ac, "le", "a") {
		t.Fatal("the refused undo wrote")
	}

	li := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:admin", []string{"le"}, []string{"read", "append"}, map[string]any{"enc": jwk, "rules": rules})))
	if h, err := li.Head(ctx, "le", "keyring"); err == nil && h.State != client.NotFound {
		t.Fatalf("li reads the keyring: %+v", h)
	}
	lx := li.E2E(priv)
	if _, err := li.PlanUndo(ctx, "le", g, client.UndoE2E(lx)); !errors.Is(err, client.ErrNeedResources) {
		t.Fatalf("without resources: %v", err)
	}
	u := must(li.Undo(ctx, "le", g, client.UndoResources("a"), client.UndoE2E(lx)))
	if u.Plan.Level != "e2e" || u.Plan.Source != "resources" {
		t.Fatalf("plan %+v", u.Plan)
	}
	_, d := must2(x.LoadE2E(ctx, "le", "a"))
	sameDoc(t, "undone", d.Value, map[string]any{"n": 0, "m": 1})
}

// §11.2 When undo is impossible, §8.6: resource logs carry no markers, so
// a limited writer can't see a gesture's revisions below a pruning horizon.
// One whose oldest entry lies at or before the oldest entry read after the
// horizon, its first entry read being that one or none following it, may
// continue or lie wholly below it, and is refused as impossible rather
// than undone in part; one after other entries is undone as usual.
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
			gw := client.NewGesture()
			w = must(li.Append(ctx, ns, "a", w.ID, nonced(ops(op("add", "/w", 1))), client.WithGesture(gw)))
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
			for _, opts := range [][]client.UndoOption{{client.UndoResources("a")}, {client.UndoResources("a"), client.UndoAuthor("user:li")}} {
				if _, err := li.Undo(ctx, ns, gw, with(opts...)...); !errors.As(err, &ie) || ie.Reason != "pruned" || ie.Resource != "a" {
					t.Fatalf("a gesture wholly below the horizon: %v", err)
				}
			}
			got, _ := docOf(t, li, ns, "a")
			sameDoc(t, "after the refusal", got, map[string]any{"n": 1, "p": 1, "q": 1, "r": 2, "w": 1})

			must(li.Undo(ctx, ns, g2, with(client.UndoResources("a"))...))
			got, _ = docOf(t, li, ns, "a")
			sameDoc(t, "after the horizon", got, map[string]any{"n": 1, "p": 1, "q": 1, "r": 1, "w": 1})
		})
	}
}

// §11.2, §8.6: a named document read from its pruning horizon with no
// entry of a gesture found in another named document is left out, so the
// UndoStack-then-Undo flow over every document a writer follows keeps
// working after one of them is pruned, at its head or below later
// entries. A gesture found in none is impossible, as it may lie wholly
// below; one whose entries there are another author's isn't found.
func TestUndoLimitedPrunedOther(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	k := clienttest.NewKey("k")
	for _, tc := range []struct {
		name, level string
		scan        []client.UndoOption
		later       bool // b gets an entry after its horizon
	}{
		{"plain", "", []client.UndoOption{client.UndoScanLog()}, false},
		{"plain-later", "", []client.UndoOption{client.UndoScanLog()}, true},
		{"sealed", "sealed", nil, false},
		{"sealed-later", "sealed", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ns := "lo-" + tc.name
			doc := map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}
			if tc.level != "" {
				doc["encryption"] = map[string]any{"level": tc.level}
			}
			must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
			only := map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"a", "b"}}}}}
			li := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:li", []string{ns}, []string{"read", "create", "append"}, only)), client.WithKeys(client.NewKeys(nil)))
			wa := must(li.Create(ctx, ns, "a", nonced(client.GenesisPatches(map[string]any{"n": 0}))))
			wb := must(li.Create(ctx, ns, "b", nonced(client.GenesisPatches(map[string]any{"p": 0}))))
			gb1, gb2 := client.NewGesture(), client.NewGesture()
			wb = must(li.Append(ctx, ns, "b", wb.ID, nonced(ops(op("replace", "/p", 1))), client.WithGesture(gb1)))
			wb = must(li.Append(ctx, ns, "b", wb.ID, nonced(ops(op("replace", "/p", 2))), client.WithGesture(gb2)))
			s.Clock.Advance(10 * time.Minute)
			pg := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:op", []string{ns}, []string{"read", "prune"})), client.WithKeys(client.NewKeys(nil)))
			must(pg.Prune(ctx, ns, "b", client.PruneRequest{Horizon: wb.ID}))
			if tc.later {
				must(li.Append(ctx, ns, "b", wb.ID, nonced(ops(op("replace", "/p", 3)))))
			}
			ga := client.NewGesture()
			must(li.Append(ctx, ns, "a", wa.ID, nonced(ops(op("replace", "/n", 1))), client.WithGesture(ga)))
			opts := append(append([]client.UndoOption{}, tc.scan...), client.UndoResources("a", "b"))

			st := must(li.UndoStack(ctx, ns, "user:li", opts...))
			top := st.Done[len(st.Done)-1]
			if top.Gesture != ga || len(top.Resources) != 1 || top.Resources[0] != "a" {
				t.Fatalf("stack top %+v", top)
			}
			u := must(li.Undo(ctx, ns, top.Target, opts...))
			if len(u.Plan.Resources) != 1 || u.Plan.Resources[0].Resource != "a" {
				t.Fatalf("plan %+v", u.Plan)
			}
			got, _ := docOf(t, li, ns, "a")
			sameDoc(t, "a undone", got, map[string]any{"n": 0})

			// gb1 lies wholly below b's horizon, and is found in no
			// document named, by li or by whoever wrote it.
			var ie *client.ImpossibleError
			for _, extra := range [][]client.UndoOption{nil, {client.UndoAuthor("user:li")}} {
				if _, err := li.Undo(ctx, ns, gb1, append(extra, opts...)...); !errors.As(err, &ie) || ie.Reason != "pruned" || ie.Resource != "b" {
					t.Fatalf("a gesture wholly below the horizon (%d): %v", len(extra), err)
				}
			}
			// ga by someone else: its entries are li's, so it isn't found.
			if _, err := li.Undo(ctx, ns, ga, append([]client.UndoOption{client.UndoAuthor("user:op")}, opts...)...); !errors.Is(err, client.ErrGestureNotFound) {
				t.Fatalf("another author's gesture: %v", err)
			}
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

// §11.2, §7.4 (v0.55): a writer limited to some resources learns the
// namespace's opsPerSet from GET /ns/{ns}/principal, and splits an inverse
// that the defaults would send as one step the server refuses.
func TestUndoLimitedWriterLimits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	k := clienttest.NewKey("k")
	opc := s.Client(t, client.WithBearer(s.OperatorGrant(t, "ul")))
	must(opc.CreateNamespace(ctx, "ul", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "limits": map[string]any{"opsPerSet": 4}}))
	only := map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}}
	li := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:li", []string{"ul"}, []string{"read", "create", "append"}, only)))
	if _, err := li.NSHead(ctx, "ul"); err == nil {
		t.Fatal("li reads the namespace")
	}
	w := must(li.Create(ctx, "ul", "a", nonced(client.GenesisPatches(map[string]any{"n": 1}))))
	g := client.NewGesture()
	must(li.Append(ctx, "ul", "a", w.ID, ops(op("add", "/p", 1), op("add", "/q", 2), op("add", "/r", 3), op("add", "/s", 4)), client.WithGesture(g)))
	plan := must(li.PlanUndo(ctx, "ul", g, client.UndoResources("a"), client.UndoScanLog()))
	steps := plan.Resources[0].Steps
	if len(steps) < 2 {
		t.Fatalf("one step for an inverse over opsPerSet: %+v", steps)
	}
	for _, st := range steps {
		if n := len(st.Patches.([]any)); n > 4 {
			t.Fatalf("a step of %d operations: %+v", n, steps)
		}
	}
	must(li.Undo(ctx, "ul", g, client.UndoResources("a"), client.UndoScanLog()))
	doc, _ := docOf(t, li, "ul", "a")
	if doc["n"] != 1.0 || doc["p"] != nil || doc["s"] != nil {
		t.Fatalf("undone %v", doc)
	}
}
