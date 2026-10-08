package client_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// §7.2, §7.4, §7.5 (v0.39): the client sends gestures on writes and batch
// steps, reads them back from write results, resource and namespace logs
// (a batch's gestures map), and lists a gesture's revisions page by page.
func TestGestures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LogPageSize: 2})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "g", map[string]any{}))
	g1, g2, g3 := client.NewGesture(), client.NewGesture(), client.NewGesture()
	if !client.ValidGesture(g1) || g1 == g2 || client.ValidGesture("ABC") {
		t.Fatalf("gesture ids %q %q", g1, g2)
	}

	// Single writes: create, append, delete and restore in gesture g1.
	w0 := must(c.CreateDoc(ctx, "g", "a", map[string]any{"n": 0}, client.WithGesture(g1)))
	if w0.Gesture != g1 || w0.Undoes != "" || w0.Entry == nil || w0.Entry.Gesture != g1 {
		t.Fatalf("create %+v %+v", w0, w0.Entry)
	}
	w1 := must(c.Append(ctx, "g", "a", w0.ID, ops(op("replace", "/n", 1)), client.WithGesture(g1)))
	del := must(c.Delete(ctx, "g", "a", w1.ID, client.WithGesture(g1)))
	if del.Gesture != g1 {
		t.Fatalf("delete %+v", del)
	}
	res := must(c.Restore(ctx, "g", "a", del.ID, []any{}, client.WithGesture(g1)))
	// The same patch set without a gesture has the same id (§3.3).
	plain := must(c.CreateDoc(ctx, "g", "b", map[string]any{"n": 0}))
	if plain.ID != w0.ID || plain.Gesture != "" {
		t.Fatalf("ids depend on gestures: %s %s", plain.ID, w0.ID)
	}
	// An idempotent retry is answered with the entry as first recorded.
	retry := must(c.Append(ctx, "g", "a", w0.ID, ops(op("replace", "/n", 1)), client.WithGesture(g2)))
	if !retry.Replayed() || retry.Gesture != g1 || retry.Entry.Gesture != g1 {
		t.Fatalf("retry %+v", retry)
	}

	// An undo of g1, in gesture g2, as one batch: the batch default, an
	// item default and step overrides, with the step forms of before.
	br := must(c.Batch(ctx, "g", client.BatchRequest{Gesture: g2, Undoes: g1, Items: []client.BatchItem{
		{Resource: "a", IfMatch: res.ID, Steps: []client.Step{client.PatchStep(ops(op("replace", "/n", 0))), client.DeleteStep()}},
		{Resource: "c", IfNoneMatch: true, Gesture: g3, Steps: []client.Step{
			client.PatchStep(client.GenesisPatches(map[string]any{})),
			client.PatchStep(ops(op("add", "/x", 1))).WithGesture(g2, ""),
		}},
	}}, false))
	alog := must(c.Log(ctx, "g", "a", "", ""))
	want := []client.StepGesture{{g1, ""}, {g1, ""}, {g1, ""}, {g1, ""}, {g2, g1}, {g2, g1}}
	if len(alog) != len(want) {
		t.Fatalf("log of a: %d entries", len(alog))
	}
	for i, e := range alog {
		if e.Gesture != want[i].Gesture || e.Undoes != want[i].Undoes {
			t.Fatalf("entry %d of a: %q %q, want %+v", i, e.Gesture, e.Undoes, want[i])
		}
	}
	clog := must(c.Log(ctx, "g", "c", "", ""))
	if clog[0].Gesture != g3 || clog[0].Undoes != g1 || clog[1].Gesture != g2 || clog[1].Undoes != g1 {
		t.Fatalf("log of c %+v", clog)
	}
	nlog := must(c.NSLog(ctx, "g", br.NSID, ""))
	for _, e := range nlog {
		switch {
		case e.Kind == "head" && e.Resource == "b", e.Kind == "config":
			if e.Gesture != "" || e.Gestures != nil {
				t.Fatalf("entry without gestures %+v", e)
			}
		case e.Kind == "head" || e.Kind == "tombstone":
			if e.Gesture != g1 || e.Undoes != "" {
				t.Fatalf("single write %+v", e)
			}
		case e.Kind == "batch":
			got := e.Gestures
			if len(got) != 2 || len(got["a"]) != 2 || got["a"][1] != (client.StepGesture{g2, g1}) ||
				got["c"][0] != (client.StepGesture{g3, g1}) || got["c"][1] != (client.StepGesture{g2, g1}) {
				t.Fatalf("batch gestures %+v", got)
			}
		}
	}

	// GET /ns/{ns}/gestures/{gesture}, two to a page: g1's own revisions,
	// then those undoing it (a batch's rows step by step, items in resource
	// order), oldest first, each with its ns_id.
	list := must(c.Gestures(ctx, "g", g1))
	if len(list) != 8 {
		t.Fatalf("gesture g1: %d entries %+v", len(list), list)
	}
	if list[0].ID != w0.ID || list[0].Resource != "a" || list[0].Kind != "rev" || list[0].NSID != w0.NSID || list[0].Author != "alice" ||
		list[2].Kind != "tombstone" || list[2].NSID != del.NSID || list[4].Undoes != g1 || list[4].NSID != br.NSID || list[7].Resource != "c" {
		t.Fatalf("gesture g1 %+v", list)
	}
	page, next := must2(c.GesturesPage(ctx, "g", g1, ""))
	if len(page) != 2 || next != "a/"+w1.ID {
		t.Fatalf("first page %v %q", page, next)
	}
	if none := must(c.Gestures(ctx, "g", client.NewGesture())); len(none) != 0 {
		t.Fatalf("unknown gesture %v", none)
	}
}

// §7.4, §E.4 (v0.39): sealed logs carry gestures inside their sealed
// entries, and the gesture listing isn't offered there (404).
func TestGesturesSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t)})
	c := s.Client(t, client.WithAuthor("alice")).With(client.WithKeys(client.NewKeys(nil)))
	must(c.CreateNamespace(ctx, "s", map[string]any{"encryption": map[string]any{"level": "sealed"}}))
	g := client.NewGesture()
	w := must(c.Create(ctx, "s", "a", nonced(client.GenesisPatches(map[string]any{})), client.WithGesture(g)))
	br := must(c.Batch(ctx, "s", client.BatchRequest{Undoes: g, Items: []client.BatchItem{
		{Resource: "a", IfMatch: w.ID, Steps: []client.Step{client.PatchStep(nonced(ops(op("add", "/x", 1))))}}}}, false))
	lg := must(c.Log(ctx, "s", "a", "", ""))
	if len(lg) != 2 || lg[0].Gesture != g || lg[1].Undoes != g || lg[1].Gesture != "" {
		t.Fatalf("sealed log %+v", lg)
	}
	nl := must(c.NSLog(ctx, "s", br.NSID, ""))
	if e := nl[len(nl)-2]; e.Gesture != g {
		t.Fatalf("sealed single write %+v", e)
	}
	if e := nl[len(nl)-1]; e.Gestures["a"][0] != (client.StepGesture{Undoes: g}) {
		t.Fatalf("sealed batch %+v", e)
	}
	if _, err := c.Gestures(ctx, "s", g); !client.IsNotFound(err) {
		t.Fatalf("listing in a sealed namespace: %v", err)
	}
}

// §7.2, §E.4 (v0.39): at E3 the server stores and serves gestures in
// plaintext beside the sealed patch sets; the listing isn't offered.
func TestGesturesE2E(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	admin := clienttest.NewKey("admin")
	opc := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e")))
	must(opc.CreateNamespace(ctx, "e", map[string]any{"keys": []any{admin.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}))
	jwk, priv, _ := seal.GenerateRecipient()
	all := []string{"read", "create", "append", "restore", "delete", "config", "branch", "purge", "prune", "export"}
	ac := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:admin", []string{"e"}, all, map[string]any{"enc": jwk})))
	x := ac.E2E(priv)
	must(x.InitKeyring(ctx, "e"))
	g := client.NewGesture()
	w0 := must(x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 0}, client.WithGesture(g)))
	w1 := must(x.AppendSealed(ctx, "e", "d", w0.ID, ops(op("replace", "/n", 1)), client.WithUndoes(g)))
	if w0.Gesture != g || w1.Undoes != g {
		t.Fatalf("e2e writes %+v %+v", w0, w1)
	}
	lg := must(ac.Log(ctx, "e", "d", w1.ID, ""))
	if len(lg) != 2 || lg[0].Gesture != g || lg[1].Undoes != g {
		t.Fatalf("e2e log %+v", lg)
	}
	nl := must(ac.NSLog(ctx, "e", w1.NSID, w0.NSID))
	if len(nl) != 1 || nl[0].Undoes != g {
		t.Fatalf("e2e namespace log %+v", nl)
	}
	if _, err := ac.Gestures(ctx, "e", g); !client.IsNotFound(err) {
		t.Fatalf("listing in an e2e namespace: %v", err)
	}
}
