package client_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// docOf loads ns/name and returns its document (the last live one when
// tombstoned) and state.
func docOf(t *testing.T, c *client.Client, ns, name string) (map[string]any, client.State) {
	t.Helper()
	ctx := context.Background()
	h := must(c.Head(ctx, ns, name))
	id := h.ID
	if h.State == client.Tombstoned {
		id = h.Last
	} else if h.State != client.Live {
		return nil, h.State
	}
	d := must(c.Doc(ctx, ns, name, id))
	m, _ := d.Value.(map[string]any)
	return m, h.State
}

func sameDoc(t *testing.T, what string, got, want any) {
	t.Helper()
	g, w := jsonv.FromGo(got), jsonv.FromGo(want)
	if m, ok := g.(map[string]any); ok {
		delete(m, "$nonce")
	}
	if !jsonv.Equal(g, w) {
		t.Fatalf("%s: %s, want %s", what, jsonv.Canonical(g), jsonv.Canonical(w))
	}
}

func head(t *testing.T, c *client.Client, ns, name string) string {
	t.Helper()
	return must(c.Head(context.Background(), ns, name)).ID
}

// §11.2: a gesture of two saves to one resource is undone by one batch
// written with a fresh gesture and Undoes, found through the gestures
// endpoint.
func TestUndoSingleResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "u", map[string]any{}))
	w := must(c.CreateDoc(ctx, "u", "a", map[string]any{"title": "x", "n": 0}))
	g := client.NewGesture()
	w = must(c.Append(ctx, "u", "a", w.ID, ops(op("replace", "/title", "y"), op("add", "/tags", []any{"t"})), client.WithGesture(g)))
	must(c.Append(ctx, "u", "a", w.ID, ops(op("replace", "/n", 1)), client.WithGesture(g)))

	plan := must(c.PlanUndo(ctx, "u", g))
	if plan.Source != "gestures" || plan.Author != "alice" || len(plan.Resources) != 1 || plan.Err() != nil {
		t.Fatalf("plan %+v", plan)
	}
	if r := plan.Resources[0]; strings.Join(r.Writes, ",") != "/n,/tags,/title" || len(r.Entries) != 2 {
		t.Fatalf("resource plan %+v", r)
	}
	res := must(c.Undo(ctx, "u", g))
	if !client.ValidGesture(res.Gesture) || res.Gesture == g || res.Attempts != 1 {
		t.Fatalf("result %+v", res)
	}
	doc, _ := docOf(t, c, "u", "a")
	sameDoc(t, "undone", doc, map[string]any{"title": "x", "n": 0})
	lg := must(c.Log(ctx, "u", "a", "", ""))
	last := lg[len(lg)-1]
	if last.Gesture != res.Gesture || last.Undoes != g || last.Author != "alice" {
		t.Fatalf("undo entry %+v", last)
	}
	// Undoing again finds the undo in the log: a conflict, not a second undo.
	if _, err := c.Undo(ctx, "u", g); !client.IsUndoConflict(err) {
		t.Fatalf("second undo: %v", err)
	} else {
		var ce *client.ConflictError
		errors.As(err, &ce)
		if ce.Conflicts[0].Kind != "undone" {
			t.Fatalf("second undo conflicts %+v", ce.Conflicts)
		}
	}
	if _, err := c.Undo(ctx, "u", client.NewGesture()); !errors.Is(err, client.ErrGestureNotFound) {
		t.Fatalf("unknown gesture: %v", err)
	}
}

// §11.2: a gesture across several saves and resources, with a create; edits
// others made to other paths, between the gesture's saves and after them,
// are kept; the undo is one batch.
func TestUndoMultiResourceKeepsOthers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	alice := s.Client(t, client.WithAuthor("alice"))
	bob := s.Client(t, client.WithAuthor("bob"))
	must(alice.CreateNamespace(ctx, "u", map[string]any{}))
	must(alice.CreateDoc(ctx, "u", "a", map[string]any{"t": 1, "o": 1}))
	must(alice.CreateDoc(ctx, "u", "b", map[string]any{"t": 1}))
	g := client.NewGesture()
	must(alice.Append(ctx, "u", "a", head(t, alice, "u", "a"), ops(op("replace", "/t", 2)), client.WithGesture(g)))
	must(bob.Append(ctx, "u", "a", head(t, bob, "u", "a"), ops(op("replace", "/o", 2))))
	// A save of the same gesture as a batch: b and a new resource c.
	must(alice.Batch(ctx, "u", client.BatchRequest{Gesture: g, Items: []client.BatchItem{
		{Resource: "b", IfMatch: head(t, alice, "u", "b"), Steps: []client.Step{client.PatchStep(ops(op("replace", "/t", 2)))}},
		{Resource: "c", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"new": true}))}},
	}}, false))
	must(alice.Append(ctx, "u", "a", head(t, alice, "u", "a"), ops(op("replace", "/t", 3)), client.WithGesture(g)))
	must(bob.Append(ctx, "u", "b", head(t, bob, "u", "b"), ops(op("add", "/x", 1))))

	// Bob's view (no gesture endpoint use): the namespace log scan finds
	// the same gesture, and attributes it to alice.
	scan := must(bob.PlanUndo(ctx, "u", g, client.UndoScanLog()))
	if scan.Source != "log" || scan.Author != "alice" || len(scan.Resources) != 3 || len(scan.Batch.Items) != 3 {
		t.Fatalf("scan plan %+v", scan)
	}
	res := must(alice.Undo(ctx, "u", g))
	if len(res.Batch.Items) != 3 || res.Batch.NSID == "" {
		t.Fatalf("batch %+v", res.Batch)
	}
	a, _ := docOf(t, alice, "u", "a")
	sameDoc(t, "a", a, map[string]any{"t": 1, "o": 2})
	b, _ := docOf(t, alice, "u", "b")
	sameDoc(t, "b", b, map[string]any{"t": 1, "x": 1})
	cdoc, st := docOf(t, alice, "u", "c")
	if st != client.Tombstoned {
		t.Fatalf("c is %v, want deleted", st)
	}
	sameDoc(t, "c's last document", cdoc, map[string]any{"new": true})
}

// §11.2 The guard: a later write to a path the gesture wrote, or a later
// delete, is a conflict listing the entries; nothing is written.
func TestUndoConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	alice := s.Client(t, client.WithAuthor("alice"))
	bob := s.Client(t, client.WithAuthor("bob"))
	must(alice.CreateNamespace(ctx, "u", map[string]any{}))
	must(alice.CreateDoc(ctx, "u", "a", map[string]any{"t": 1, "sub": map[string]any{"k": 1}}))
	must(alice.CreateDoc(ctx, "u", "b", map[string]any{"t": 1}))
	g := client.NewGesture()
	must(alice.Append(ctx, "u", "a", head(t, alice, "u", "a"), ops(op("replace", "/sub/k", 2)), client.WithGesture(g)))
	must(alice.Append(ctx, "u", "b", head(t, alice, "u", "b"), ops(op("replace", "/t", 2)), client.WithGesture(g)))
	bg := client.NewGesture()
	must(bob.Append(ctx, "u", "a", head(t, bob, "u", "a"), ops(op("replace", "/sub", map[string]any{"k": 9})), client.WithGesture(bg)))
	must(bob.Delete(ctx, "u", "b", head(t, bob, "u", "b")))

	plan := must(alice.PlanUndo(ctx, "u", g))
	if len(plan.Conflicts) != 2 {
		t.Fatalf("conflicts %+v", plan.Conflicts)
	}
	byRes := map[string]client.UndoConflict{}
	for _, c := range plan.Conflicts {
		byRes[c.Resource] = c
	}
	if c := byRes["a"]; c.Kind != "overlap" || c.Author != "bob" || c.Gesture != bg || strings.Join(c.Paths, ",") != "/sub,/sub/k" {
		t.Fatalf("conflict on a %+v", c)
	}
	if c := byRes["b"]; c.Kind != "deleted" {
		t.Fatalf("conflict on b %+v", c)
	}
	before := head(t, alice, "u", "a")
	_, err := alice.Undo(ctx, "u", g)
	var ce *client.ConflictError
	if !errors.As(err, &ce) || len(ce.Conflicts) != 2 || client.IsUndoImpossible(err) {
		t.Fatalf("undo: %v", err)
	}
	if head(t, alice, "u", "a") != before {
		t.Fatal("a conflicting undo wrote")
	}
}

// §11.2, §F.3: writes to array elements count for the whole array. An
// append is undone by restoring the array, an insert by someone else
// after the gesture conflicts, a move is moved back.
func TestUndoArrays(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	alice := s.Client(t, client.WithAuthor("alice"))
	bob := s.Client(t, client.WithAuthor("bob"))
	must(alice.CreateNamespace(ctx, "u", map[string]any{}))
	must(alice.CreateDoc(ctx, "u", "a", map[string]any{"items": []any{"a", "b", "c"}, "other": 1}))

	g1 := client.NewGesture()
	must(alice.Append(ctx, "u", "a", head(t, alice, "u", "a"), ops(op("add", "/items/-", "d")), client.WithGesture(g1)))
	must(bob.Append(ctx, "u", "a", head(t, bob, "u", "a"), ops(op("replace", "/other", 2))))
	plan := must(alice.PlanUndo(ctx, "u", g1))
	if w := plan.Resources[0].Writes; len(w) != 1 || w[0] != "/items" {
		t.Fatalf("widened writes %v", w)
	}
	must(alice.Undo(ctx, "u", g1))
	a, _ := docOf(t, alice, "u", "a")
	sameDoc(t, "after undoing the append", a, map[string]any{"items": []any{"a", "b", "c"}, "other": 2})

	// A move: inverted as a move back.
	g2 := client.NewGesture()
	must(alice.Append(ctx, "u", "a", head(t, alice, "u", "a"), []any{map[string]any{"op": "move", "from": "/items/0", "path": "/items/2"}}, client.WithGesture(g2)))
	plan = must(alice.PlanUndo(ctx, "u", g2))
	steps := plan.Resources[0].Steps
	if len(steps) != 1 || !strings.Contains(string(jsonv.Canonical(jsonv.FromGo(steps[0].Patches))), `"op":"move"`) {
		t.Fatalf("move inverse %+v", steps)
	}
	must(alice.Undo(ctx, "u", g2))
	a, _ = docOf(t, alice, "u", "a")
	sameDoc(t, "after moving back", a, map[string]any{"items": []any{"a", "b", "c"}, "other": 2})

	// An element edited in the gesture, then an insert at 0 by bob: the
	// indices shifted, so it is a conflict on the whole array.
	g3 := client.NewGesture()
	must(alice.Append(ctx, "u", "a", head(t, alice, "u", "a"), ops(op("replace", "/items/1", "B")), client.WithGesture(g3)))
	must(bob.Append(ctx, "u", "a", head(t, bob, "u", "a"), ops(op("add", "/items/0", "z"))))
	_, err := alice.Undo(ctx, "u", g3)
	var ce *client.ConflictError
	if !errors.As(err, &ce) || ce.Conflicts[0].Kind != "overlap" || strings.Join(ce.Conflicts[0].Paths, ",") != "/items" {
		t.Fatalf("insert after an element edit: %v", err)
	}
}

// §11.2 The inverse: a tombstone is undone by a restore with [], a restore
// by the inverse of its patches and a delete, a genesis by a delete.
func TestUndoDeleteRestoreCreate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "u", map[string]any{}))

	// Delete.
	w := must(c.CreateDoc(ctx, "u", "d", map[string]any{"n": 1}))
	gd := client.NewGesture()
	must(c.Delete(ctx, "u", "d", w.ID, client.WithGesture(gd)))
	must(c.Undo(ctx, "u", gd))
	if doc, st := docOf(t, c, "u", "d"); st != client.Live {
		t.Fatalf("undo of a delete: %v", st)
	} else {
		sameDoc(t, "restored", doc, map[string]any{"n": 1})
	}

	// Restore (with patches).
	w = must(c.CreateDoc(ctx, "u", "r", map[string]any{"n": 1}))
	del := must(c.Delete(ctx, "u", "r", w.ID))
	gr := client.NewGesture()
	must(c.Restore(ctx, "u", "r", del.ID, ops(op("replace", "/n", 2)), client.WithGesture(gr)))
	plan := must(c.PlanUndo(ctx, "u", gr))
	if st := plan.Resources[0].Steps; len(st) != 2 || st[0].Delete || !st[1].Delete {
		t.Fatalf("restore inverse %+v", st)
	}
	must(c.Undo(ctx, "u", gr))
	if doc, st := docOf(t, c, "u", "r"); st != client.Tombstoned {
		t.Fatalf("undo of a restore: %v", st)
	} else {
		sameDoc(t, "last live document", doc, map[string]any{"n": 1})
	}

	// Create, edit, delete and restore in one gesture: deleted in the end.
	gc := client.NewGesture()
	w = must(c.CreateDoc(ctx, "u", "c", map[string]any{"n": 1}, client.WithGesture(gc)))
	w = must(c.Append(ctx, "u", "c", w.ID, ops(op("replace", "/n", 2)), client.WithGesture(gc)))
	del = must(c.Delete(ctx, "u", "c", w.ID, client.WithGesture(gc)))
	must(c.Restore(ctx, "u", "c", del.ID, []any{}, client.WithGesture(gc)))
	must(c.Undo(ctx, "u", gc))
	if doc, st := docOf(t, c, "u", "c"); st != client.Tombstoned {
		t.Fatalf("undo of a create: %v", st)
	} else {
		sameDoc(t, "the genesis document", doc, map[string]any{"n": 1})
	}
}

// §11.2 Redo: undoing the undo; and the redo itself can be undone.
func TestRedo(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "u", map[string]any{}))
	w := must(c.CreateDoc(ctx, "u", "a", map[string]any{"n": 0}))
	g := client.NewGesture()
	must(c.Append(ctx, "u", "a", w.ID, ops(op("replace", "/n", 1), op("add", "/m", true)), client.WithGesture(g)))
	if _, err := c.Redo(ctx, "u", g); !errors.Is(err, client.ErrNotUndone) {
		t.Fatalf("redo before undo: %v", err)
	}
	u := must(c.Undo(ctx, "u", g))
	r := must(c.Redo(ctx, "u", g))
	if r.Plan.Gesture != u.Gesture {
		t.Fatalf("redo undid %s, want the undo %s", r.Plan.Gesture, u.Gesture)
	}
	doc, _ := docOf(t, c, "u", "a")
	sameDoc(t, "redone", doc, map[string]any{"n": 1, "m": true})
	must(c.Undo(ctx, "u", r.Gesture, client.UndoScanLog()))
	doc, _ = docOf(t, c, "u", "a")
	sameDoc(t, "undone again", doc, map[string]any{"n": 0})
}

// §11.2 Redo: an author's stack, rebuilt from the log, counts that
// author's undos and redos; an undo by someone else is shown as such and
// keeps the action on the stack; Undoes naming a missing gesture is
// ignored.
func TestUndoStack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	alice := s.Client(t, client.WithAuthor("alice"))
	bob := s.Client(t, client.WithAuthor("bob"))
	must(alice.CreateNamespace(ctx, "u", map[string]any{}))
	must(alice.CreateDoc(ctx, "u", "a", map[string]any{"a": 0, "b": 0, "c": 0, "x": 0}))
	edit := func(c *client.Client, path string, v any, opts ...client.WriteOption) {
		t.Helper()
		must(c.Append(ctx, "u", "a", head(t, c, "u", "a"), ops(op("replace", path, v)), opts...))
	}
	g1, g2, g3, gx := client.NewGesture(), client.NewGesture(), client.NewGesture(), client.NewGesture()
	edit(alice, "/a", 1, client.WithGesture(g1))
	edit(alice, "/b", 1, client.WithGesture(g2))
	edit(alice, "/c", 1, client.WithGesture(g3))
	edit(alice, "/x", 1, client.WithGesture(gx), client.WithUndoes(client.NewGesture())) // names a missing gesture
	u3 := must(alice.Undo(ctx, "u", g3))
	b2 := must(bob.Undo(ctx, "u", g2))
	must(alice.Undo(ctx, "u", g1))
	r1 := must(alice.Redo(ctx, "u", g1))

	st := must(alice.UndoStack(ctx, "u", "alice"))
	var done []string
	for _, it := range st.Done {
		done = append(done, it.Gesture)
	}
	if strings.Join(done, ",") != strings.Join([]string{g2, gx, g1}, ",") {
		t.Fatalf("done %v, want g2 gx g1", done)
	}
	if it := st.Done[0]; len(it.UndoneBy) != 1 || it.UndoneBy[0].Author != "bob" || it.UndoneBy[0].Gesture != b2.Gesture || it.Target != g2 {
		t.Fatalf("g2 %+v", it)
	}
	if it := st.Done[2]; it.Target != r1.Gesture || len(it.Chain) != 2 {
		t.Fatalf("g1 %+v", it)
	}
	if len(st.Undone) != 1 || st.Undone[0].Gesture != g3 || st.Undone[0].Target != u3.Gesture || st.Undone[0].Resources[0] != "a" {
		t.Fatalf("undone %+v", st.Undone)
	}
	// Bob's stack: his undo of alice's gesture is an action of his own.
	bs := must(bob.UndoStack(ctx, "u", "bob"))
	if len(bs.Done) != 1 || bs.Done[0].Gesture != b2.Gesture || len(bs.Undone) != 0 {
		t.Fatalf("bob's stack %+v", bs)
	}
	// Undo the last of alice's stack (the redo of g1), then redo it from
	// the rebuilt stack.
	must(alice.Undo(ctx, "u", st.Done[2].Target))
	st = must(alice.UndoStack(ctx, "u", "alice"))
	if len(st.Undone) != 2 || st.Undone[1].Gesture != g1 {
		t.Fatalf("after undoing g1's redo %+v", st.Undone)
	}
	must(alice.Undo(ctx, "u", st.Undone[1].Target))
	doc, _ := docOf(t, alice, "u", "a")
	sameDoc(t, "final", doc, map[string]any{"a": 1, "b": 0, "c": 0, "x": 1})
}

// §11.2 The guard: the batch names the checked heads, so a write landing
// in between fails it with 412, and the undo is planned and sent again.
func TestUndoRetriesOn412(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var other atomic.Pointer[client.Client]
	var fired atomic.Bool
	s := clienttest.New(t, clienttest.Options{Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && r.URL.Path == "/ns/u/batch" && fired.CompareAndSwap(false, true) {
				bob := other.Load()
				hd := must(bob.Head(r.Context(), "u", "a"))
				must(bob.Append(r.Context(), "u", "a", hd.ID, ops(op("add", "/bob", true))))
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
	res := must(alice.Undo(ctx, "u", g))
	if res.Attempts != 2 || !fired.Load() {
		t.Fatalf("attempts %d", res.Attempts)
	}
	doc, _ := docOf(t, alice, "u", "a")
	sameDoc(t, "after the race", doc, map[string]any{"n": 0, "bob": true})
	// Without retries the 412 is returned.
	g2 := client.NewGesture()
	must(alice.Append(ctx, "u", "a", head(t, alice, "u", "a"), ops(op("replace", "/n", 2)), client.WithGesture(g2)))
	fired.Store(false)
	if _, err := alice.Undo(ctx, "u", g2, client.UndoRetries(0)); !client.IsStale(errors.Unwrap(err)) {
		t.Fatalf("no retries: %v", err)
	}
}

// §11.2 When undo is impossible: a revision of the gesture lies below the
// pruning horizon.
func TestUndoPrunedImpossible(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "u", map[string]any{}))
	w := must(c.CreateDoc(ctx, "u", "a", map[string]any{"n": 0}))
	g := client.NewGesture()
	w = must(c.Append(ctx, "u", "a", w.ID, ops(op("replace", "/n", 1)), client.WithGesture(g)))
	var revs []string
	for i := range 3 {
		w = must(c.Append(ctx, "u", "a", w.ID, ops(op("add", "/m", i))))
		revs = append(revs, w.ID)
	}
	s.Clock.Advance(10 * time.Minute)
	must(c.Prune(ctx, "u", "a", client.PruneRequest{Horizon: revs[1]}))
	for _, opts := range [][]client.UndoOption{nil, {client.UndoScanLog()}} {
		_, err := c.Undo(ctx, "u", g, opts...)
		var ie *client.ImpossibleError
		if !errors.As(err, &ie) || ie.Reason != "pruned" || ie.Resource != "a" || client.IsUndoConflict(err) {
			t.Fatalf("pruned (%d options): %v", len(opts), err)
		}
	}
	// A gesture after the horizon is still undone, reading the log from it.
	g2 := client.NewGesture()
	must(c.Append(ctx, "u", "a", w.ID, ops(op("replace", "/n", 5)), client.WithGesture(g2)))
	must(c.Undo(ctx, "u", g2))
	doc, _ := docOf(t, c, "u", "a")
	sameDoc(t, "after the horizon", doc, map[string]any{"n": 1, "m": 2})
}

// §11.2, §C.7, §7.4: in a sealed namespace the gesture isn't listed, so it
// is found by scanning the namespace log; every patch set of the inverse
// carries a fresh $nonce, never an old one.
func TestUndoSealedLogScan(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t), LogPageSize: 2})
	alice := s.Client(t, client.WithAuthor("alice")).With(client.WithKeys(client.NewKeys(nil)))
	bob := s.Client(t, client.WithAuthor("bob")).With(client.WithKeys(client.NewKeys(nil)))
	must(alice.CreateNamespace(ctx, "s", map[string]any{"encryption": map[string]any{"level": "sealed"}}))
	wa := must(alice.Create(ctx, "s", "a", nonced(client.GenesisPatches(map[string]any{"t": 1, "o": 1}))))
	wb := must(alice.Create(ctx, "s", "b", nonced(client.GenesisPatches(map[string]any{"t": 1}))))
	g := client.NewGesture()
	wa = must(alice.Append(ctx, "s", "a", wa.ID, nonced(ops(op("replace", "/t", 2))), client.WithGesture(g)))
	must(bob.Append(ctx, "s", "a", wa.ID, nonced(ops(op("replace", "/o", 2)))))
	must(alice.Batch(ctx, "s", client.BatchRequest{Gesture: g, Items: []client.BatchItem{
		{Resource: "b", IfMatch: wb.ID, Steps: []client.Step{client.PatchStep(nonced(ops(op("replace", "/t", 2))))}}}}, false))
	var nonces []string
	for _, r := range []string{"a", "b"} {
		for _, e := range must(alice.Log(ctx, "s", r, "", "")) {
			d := must(alice.Doc(ctx, "s", r, e.ID))
			nonces = append(nonces, d.Value.(map[string]any)["$nonce"].(string))
		}
	}

	res := must(alice.Undo(ctx, "s", g))
	if res.Plan.Source != "log" || len(res.Batch.Items) != 2 {
		t.Fatalf("sealed undo %+v", res.Plan)
	}
	for _, it := range res.Plan.Batch.Items {
		for _, st := range it.Steps {
			if !strings.Contains(string(jsonv.Canonical(jsonv.FromGo(st.Patches))), `"path":"/$nonce"`) {
				t.Fatalf("a step without a fresh nonce: %v", st.Patches)
			}
		}
	}
	for _, r := range []string{"a", "b"} {
		d := must(alice.Doc(ctx, "s", r, head(t, alice, "s", r))).Value.(map[string]any)
		n, _ := d["$nonce"].(string)
		if !seal.ValidNonce(n) {
			t.Fatalf("%s: no fresh nonce %v", r, d)
		}
		for _, old := range nonces {
			if n == old {
				t.Fatalf("%s: an old nonce restored", r)
			}
		}
	}
	a, _ := docOf(t, alice, "s", "a")
	sameDoc(t, "a", a, map[string]any{"t": 1, "o": 2})
	b, _ := docOf(t, alice, "s", "b")
	sameDoc(t, "b", b, map[string]any{"t": 1})
	lg := must(alice.Log(ctx, "s", "b", "", ""))
	if e := lg[len(lg)-1]; e.Undoes != g || e.Gesture != res.Gesture {
		t.Fatalf("sealed undo entry %+v", e)
	}
	// The stack is rebuilt from the sealed namespace log too.
	st := must(alice.UndoStack(ctx, "s", "alice"))
	if len(st.Undone) != 1 || st.Undone[0].Gesture != g || len(st.Undone[0].Resources) != 2 {
		t.Fatalf("sealed stack %+v", st)
	}
}

// §6.6, §11.2: a large inverse is split into chained steps within the
// namespace's opsPerSet.
func TestUndoSplitsLargeInverse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "u", map[string]any{"limits": map[string]any{"opsPerSet": 3}}))
	doc := map[string]any{}
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		doc[k] = 0
	}
	w := must(c.CreateDoc(ctx, "u", "a", doc))
	g := client.NewGesture()
	w = must(c.Append(ctx, "u", "a", w.ID, ops(op("replace", "/a", 1), op("replace", "/b", 1), op("replace", "/c", 1)), client.WithGesture(g)))
	w = must(c.Append(ctx, "u", "a", w.ID, ops(op("replace", "/d", 1), op("replace", "/e", 1), op("replace", "/f", 1)), client.WithGesture(g)))
	must(c.Append(ctx, "u", "a", w.ID, ops(op("remove", "/g", nil)), client.WithGesture(g)))
	res := must(c.Undo(ctx, "u", g))
	if n := len(res.Plan.Resources[0].Steps); n != 3 {
		t.Fatalf("%d steps, want 3 of at most 3 ops", n)
	}
	got, _ := docOf(t, c, "u", "a")
	sameDoc(t, "after a split undo", got, doc)
}

// §11.2, §E.3: at E3 the inverse is computed from decrypted entries and
// written sealed, each step bound to the id of the step before.
func TestUndoE2E(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	admin := clienttest.NewKey("admin")
	opc := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e")))
	must(opc.CreateNamespace(ctx, "e", map[string]any{"keys": []any{admin.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}))
	jwk, priv, _ := seal.GenerateRecipient()
	all := []string{"read", "create", "append", "restore", "delete", "config"}
	ac := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:admin", []string{"e"}, all, map[string]any{"enc": jwk})))
	x := ac.E2E(priv)
	must(x.InitKeyring(ctx, "e"))
	w := must(x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 0, "o": 0}))
	g := client.NewGesture()
	w = must(x.AppendSealed(ctx, "e", "d", w.ID, ops(op("replace", "/n", 1)), client.WithGesture(g)))
	w = must(x.AppendSealed(ctx, "e", "d", w.ID, ops(op("replace", "/o", 1))))
	del := must(ac.Delete(ctx, "e", "d", w.ID, client.WithGesture(g)))
	_ = del
	if _, err := ac.Undo(ctx, "e", g); err == nil || !strings.Contains(err.Error(), "UndoE2E") {
		t.Fatalf("e2e without the view: %v", err)
	}
	res := must(ac.Undo(ctx, "e", g, client.UndoE2E(x)))
	if res.Plan.Source != "log" {
		t.Fatalf("e2e plan %+v", res.Plan)
	}
	h, d := must2(x.LoadE2E(ctx, "e", "d"))
	if h.State != client.Live || len(d.Flagged) != 0 {
		t.Fatalf("after the e2e undo: %+v %+v", h, d)
	}
	sameDoc(t, "e2e undone", d.Value, map[string]any{"n": 0, "o": 1})
}

// §11.2 When undo is impossible: the document's $schema was migrated since,
// and the old values no longer validate (422 invalid), which isn't a
// conflict: the migration wrote other paths.
func TestUndoInvalidImpossible(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "schemas", map[string]any{}))
	must(c.CreateNamespace(ctx, "u", map[string]any{}))
	dialect := "https://json-schema.org/draft/2020-12/schema"
	s1 := must(c.CreateDoc(ctx, "schemas", "t1", map[string]any{"$schema": dialect, "type": "object", "properties": map[string]any{"title": map[string]any{"type": "string"}}}))
	s2 := must(c.CreateDoc(ctx, "schemas", "t2", map[string]any{"$schema": dialect, "type": "object", "properties": map[string]any{"title": map[string]any{"type": "integer"}}}))
	w := must(c.CreateDoc(ctx, "u", "a", map[string]any{"$schema": "/r/schemas/t1/rev/" + s1.ID, "title": "a"}))
	g := client.NewGesture()
	w = must(c.Append(ctx, "u", "a", w.ID, ops(map[string]any{"op": "remove", "path": "/title"}), client.WithGesture(g)))
	must(c.Append(ctx, "u", "a", w.ID, ops(op("replace", "/$schema", "/r/schemas/t2/rev/"+s2.ID))))
	plan := must(c.PlanUndo(ctx, "u", g))
	if plan.Err() != nil {
		t.Fatalf("a migration of other paths conflicts: %v", plan.Err())
	}
	_, err := c.Undo(ctx, "u", g)
	var ie *client.ImpossibleError
	if !errors.As(err, &ie) || ie.Reason != "invalid" || client.IsUndoConflict(err) {
		t.Fatalf("undo after a migration: %v", err)
	}
}
