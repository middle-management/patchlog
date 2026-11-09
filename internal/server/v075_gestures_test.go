package server

import "testing"

// V75-03 (v0.75): the gestures listing's after test (§7.4) and its
// filtering for partial readers (§B.11.9 Answers).

// §7.4 (v0.75): a gestures listing's after must name a row the listing
// would give the caller: one written with the gesture or undoing it.
func TestV075GesturesAfterNamesARow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("main", map[string]any{})
	gB := "bbbbbbbbbbbbbbbbbbbbbbbbbb"
	r := e.gw("PATCH", "main", "x", "", addRoot(map[string]any{"n": 0}), map[string]string{"Gesture": gA})
	expect(t, r, 201)
	r1 := etagOf(r)
	r = e.gw("PATCH", "main", "x", r1, ops(op("replace", "/n", 1)), map[string]string{"Gesture": gB})
	expect(t, r, 201)
	r2 := etagOf(r)
	expect(t, e.get("/ns/main/gestures/"+gA+"?after=x/"+r1), 200)
	// r2 was written with gB, not gA: no row of gA's listing.
	expectCode(t, e.get("/ns/main/gestures/"+gA+"?after=x/"+r2), 404, "not_found")
	expect(t, e.get("/ns/main/gestures/"+gB+"?after=x/"+r2), 200)
}

// §B.11.9 Answers, §7.4 (scenarios 77, 86): the gestures listing shows a
// partial reader only what is visible to it: never an unplaced document,
// and an after naming one is 404. no-store.
func TestV075GesturesFiltered(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, nil)
	g := map[string]string{"Gesture": gA}
	w.put("matches", "derby", map[string]any{"title": "derby"}, g)
	op := w.put("matches", "opener", map[string]any{"title": "opener"}, g)
	all := w.get("/ns/matches/gestures/"+gA, w.admin)
	expect(t, all, 200)
	if len(all.Arr()) != 2 {
		t.Fatalf("admin %s", all.Body)
	}
	li := w.get("/ns/matches/gestures/"+gA, w.li())
	expect(t, li, 200)
	if len(li.Arr()) != 1 || li.Arr()[0].(map[string]any)["resource"] != "derby" || li.H.Get("Cache-Control") != "no-store" {
		t.Fatalf("li %v %s", li.H, li.Body)
	}
	expectCode(t, w.get("/ns/matches/gestures/"+gA+"?after=opener/"+op, w.li()), 404, "not_found")
	expect(t, w.get("/ns/matches/gestures/"+gA+"?after=opener/"+op, w.admin), 200)
}
