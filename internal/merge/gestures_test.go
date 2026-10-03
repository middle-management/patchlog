package merge_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/merge"
)

// §F.3 Attribution (v0.39): fast-forwarded and replayed revisions keep
// their source revisions' gesture and undoes in the base; squashing loses
// them.
func TestMergeCarriesGestures(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	g1, g2 := client.NewGesture(), client.NewGesture()
	// derby: fast-forward. cup: replay, since the base moves too.
	h := e.head("r7", "derby")
	w := must(e.c.Append(ctx, "r7", "derby", h.ID, ops(op("replace", "/score", "1-0")), client.WithGesture(g1)))
	must(e.c.Append(ctx, "r7", "derby", w.ID, ops(op("replace", "/score", "0-0")), client.WithGesture(g2), client.WithUndoes(g1)))
	hc := e.head("r7", "cup")
	must(e.c.Append(ctx, "r7", "cup", hc.ID, ops(op("replace", "/title", "The Cup")), client.WithGesture(g1)))
	e.append("matches", "cup", op("replace", "/score", "2-1"))

	p := e.plan("matches", "r7", merge.Options{})
	if c := classes(p); c["derby"] != merge.FastForward || c["cup"] != merge.Replay {
		t.Fatalf("classes %v", c)
	}
	must(p.Apply(ctx))
	dl := must(e.c.Log(ctx, "matches", "derby", "", ""))
	if n := len(dl); n != 3 || dl[1].Gesture != g1 || dl[2].Gesture != g2 || dl[2].Undoes != g1 || dl[1].Author != "alice" {
		t.Fatalf("fast-forwarded derby %+v", dl)
	}
	cl := must(e.c.Log(ctx, "matches", "cup", "", ""))
	if last := cl[len(cl)-1]; last.Gesture != g1 || last.Undoes != "" {
		t.Fatalf("replayed cup %+v", last)
	}
	// The batch entry records them per step (§7.4).
	nh := must(e.c.NSHead(ctx, "matches"))
	nl := must(e.c.NSLog(ctx, "matches", nh.ID, ""))
	if b := nl[len(nl)-1]; b.Kind != "batch" || len(b.Gestures["derby"]) != 2 || b.Gestures["derby"][1] != (client.StepGesture{Gesture: g2, Undoes: g1}) {
		t.Fatalf("merge batch %+v", b)
	}

	// Squashed: one new set, no gesture.
	e.branch("matches", "r8")
	h = e.head("r8", "derby")
	must(e.c.Append(ctx, "r8", "derby", h.ID, ops(op("replace", "/title", "Big Derby")), client.WithGesture(g1)))
	must(e.plan("matches", "r8", merge.Options{Squash: true}).Apply(ctx))
	dl = must(e.c.Log(ctx, "matches", "derby", "", ""))
	if last := dl[len(dl)-1]; last.Gesture != "" {
		t.Fatalf("squashed derby kept a gesture %+v", last)
	}
}
