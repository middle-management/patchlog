package server

import "testing"

// oneToken are limits that leave each principal one write per resource:
// the bucket's burst is 1 and it takes a quarter of an hour to refill.
func oneToken() map[string]any {
	return map[string]any{"ratePerResource": map[string]any{"rate": 0.001, "burst": 1.0}}
}

// spent asserts that again, a repeat of a request just refused or answered
// at step 2, finds the per-resource bucket empty: the first one drew its
// token, although it wrote nothing (§6.6 Cost).
func spent(t *testing.T, again *resp) {
	t.Helper()
	expectCode(t, again, 429, "rate")
	if again.Str("limit") != "ratePerResource" || again.H.Get("Retry-After") == "" {
		t.Fatalf("429 %v %s", again.H, again.Body)
	}
}

// §6.2 step 1, §6.6 Cost (v0.85), LIM-3, conformance scenario 81: rate
// limits come last in step 1, so a request refused in step 2 has drawn its
// tokens and keeps the deduction. A principal whose ratePerResource bucket
// for a resource holds one token and whose write is refused there (412, a
// tombstoned resource's 410, 428, a frozen namespace's 409) finds the
// bucket empty when it sends the request again: 429, not the same refusal.
func TestV085RefusedWritesDrawTokens(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"limits": oneToken()})
	other := e.create("docs", "other", map[string]any{})

	// 412: a stale If-Match.
	e.create("docs", "x", map[string]any{"n": 0.0})
	stale := func() *resp { return e.write("PATCH", "docs", "x", other, ops(op("replace", "/n", 1.0)), "bob") }
	r := stale()
	expectCode(t, r, 412, "stale")
	if r.Str("head") == "" {
		t.Fatalf("412 without head: %s", r.Body)
	}
	spent(t, stale())

	// 410: a tombstoned resource, appended to on the head it had.
	y := e.create("docs", "y", map[string]any{"n": 0.0})
	e.del("docs", "y", y, "carol")
	gone := func() *resp { return e.write("PATCH", "docs", "y", y, ops(op("replace", "/n", 1.0)), "bob") }
	expectCode(t, gone(), 410, "gone")
	spent(t, gone())

	// 428: no precondition.
	bare := func() *resp {
		return e.do(req{method: "PATCH", path: "/r/docs/z", body: addRoot(map[string]any{}), author: "bob"})
	}
	expectCode(t, bare(), 428, "precondition_required")
	spent(t, bare())

	// 409: a frozen namespace, the precondition matching.
	e.mkNS("iced", map[string]any{"limits": oneToken()})
	w := e.create("iced", "w", map[string]any{"n": 0.0})
	expect(t, e.patchNS("iced", ops(op("add", "/frozen", true)), ""), 201)
	frozen := func() *resp { return e.write("PATCH", "iced", "w", w, ops(op("replace", "/n", 1.0)), "bob") }
	expectCode(t, frozen(), 409, "frozen")
	spent(t, frozen())

	// Another principal's bucket for the same resource is its own, and
	// none of the refusals wrote anything.
	if e.head("docs", "x") == other || e.head("iced", "w") != w {
		t.Fatal("a refused write was written")
	}
	e.appendRev("docs", "x", e.head("docs", "x"), ops(op("replace", "/n", 2.0)), "dave")
}

// §6.6 Cost, §7.2 (v0.85), scenario 81: an idempotent retry is answered
// 200 at step 2 and draws its tokens like the write it repeats, for a
// single write as for a batch: with two tokens, the write and one retry
// spend them, and the next retry is 429, not another 200.
func TestV085IdempotentRetryDrawsToken(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"limits": map[string]any{"ratePerResource": map[string]any{"rate": 0.001, "burst": 2.0}}})
	create := func() *resp { return e.write("PATCH", "docs", "r", "", addRoot(map[string]any{"n": 0.0}), "bob") }
	first := create()
	expect(t, first, 201)
	again := create()
	expect(t, again, 200)
	if etagOf(again) != etagOf(first) {
		t.Fatalf("retry answered %s, the write %s", etagOf(again), etagOf(first))
	}
	spent(t, create())

	// An append and its retry, by a principal whose bucket is full.
	head := etagOf(first)
	add := func() *resp { return e.write("PATCH", "docs", "r", head, ops(op("replace", "/n", 1.0)), "carol") }
	expect(t, add(), 201)
	expect(t, add(), 200)
	spent(t, add())

	// A delete and its retry.
	head = e.head("docs", "r")
	del := func() *resp { return e.write("DELETE", "docs", "r", head, nil, "dave") }
	expect(t, del(), 200)
	expect(t, del(), 200)
	spent(t, del())
}

// §6.2 steps 1 and 2.2, §6.6 Cost (v0.85), scenario 81: a settled verb's
// 403 is a refusal of step 2, after admission, and keeps its token: an
// append grant that can't restore, writing on a tombstone. A 403 of step 1
// comes before the rate limits and draws nothing, however often it is
// repeated: the token is still there for a write the same principal may
// make.
func TestV085ForbiddenWritesAndTokens(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, map[string]any{"limits": oneToken()})
	e := f.tenv
	a := e.create("sec", "a", map[string]any{"n": 0.0}, f.adminG)
	tomb := e.del("sec", "a", a, f.issuerG)

	// Settled at step 2: the resource is tombstoned, so the write is a
	// restore, which the grant doesn't list.
	appender := e.grant(f.issuer, "user:w", []string{"sec"}, []string{"read", "append"})
	restore := func() *resp { return e.write("PATCH", "sec", "a", tomb, []any{}, appender) }
	expectCode(t, restore(), 403, "forbidden")
	spent(t, restore())

	// Refused at step 1: the grant lists no verb a create could be.
	reader := e.grant(f.issuer, "user:v", []string{"sec"}, []string{"read"})
	for i := 0; i < 3; i++ {
		expectCode(t, e.write("PATCH", "sec", "b", "", addRoot(map[string]any{}), reader), 403, "forbidden")
	}
	creator := e.grant(f.issuer, "user:v", []string{"sec"}, []string{"read", "create"})
	expect(t, e.write("PATCH", "sec", "b", "", addRoot(map[string]any{}), creator), 201)
	// And that write drew the one token the three refusals left: its
	// repeat is 429 before the retry lookup could answer it.
	spent(t, e.write("PATCH", "sec", "b", "", addRoot(map[string]any{}), creator))
}
