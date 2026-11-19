package server

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
)

// §6.6 Validation work, LIM-7, conformance scenario 89 (§C.2 item 5): a
// read, an exchange and a key request under a grant whose rule's schema
// test runs out of validationSteps fail with their usual refusals, 404
// for a resource of a private namespace and 403 for the namespace's log,
// the exchange and the keys, never 422 and never unbounded work. A
// run-out inside a not never passes the rule: the whole check fails.
func TestV086ReadCheckBudget(t *testing.T) {
	t.Parallel()
	f, mint := stepOneFixture(t)
	e := f.tenv
	e.create("sec", "x", map[string]any{"v": 1.0}, f.adminG)
	e.create("sec", "y", map[string]any{"v": 2.0}, f.adminG)
	slowP := func(levels int) map[string]any {
		return map[string]any{"op": "test", "path": "/principal", "schema": doubling(levels)}
	}
	refused := func(name, who string) {
		t.Helper()
		expectCode(t, e.get("/r/sec/x", who), 404, "not_found")
		expectCode(t, e.get("/r/sec/x/log", who), 404, "not_found")
		expectCode(t, e.get("/ns/sec/log", who), 403, "forbidden")
		expectCode(t, e.do(req{method: "POST", path: "/edge-grants", bearer: who}), 403, "forbidden")
		_, r := e.keysOf("sec", nil, who)
		expectCode(t, r, 403, "forbidden")
	}
	refused("a block rule", narrowed(t, mint("user:r", "read"), map[string]any{"rules": []any{slowP(30)}}))
	// Cut short, the test is not false: a not around it doesn't pass,
	// nor does an any beside a member that holds.
	refused("under a not", narrowed(t, mint("user:r", "read"), map[string]any{"rules": []any{map[string]any{"not": slowP(30)}}}))
	refused("beside a pass", narrowed(t, mint("user:r", "read"), map[string]any{"rules": []any{
		map[string]any{"any": []any{slowP(30), map[string]any{"op": "test", "path": "/action", "value": "read"}}}}}))

	// A role whose rule runs out: no other role makes up for it.
	expect(t, e.patchNS("sec", ops(op("add", "/roles/slow", map[string]any{"can": []any{"read"}, "rules": []any{slowP(30)}}),
		op("add", "/roles/plain", map[string]any{"can": []any{"read"}})), f.adminG), 201)
	withRoles := func(roles ...any) string {
		g, err := grant.Mint(map[string]any{"kid": "issuer", "sub": "user:r", "ns": []any{"sec"}, "roles": roles,
			"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}, f.issuer.priv)
		if err != nil {
			t.Fatal(err)
		}
		return g.Encode()
	}
	refused("its role", withRoles("slow"))
	refused("a role before another", withRoles("slow", "plain"))

	// Within the budget the same shapes read as ever.
	ok := narrowed(t, mint("user:r", "read"), map[string]any{"rules": []any{slowP(4)}})
	expect(t, e.get("/r/sec/x", ok), 302)
	expect(t, e.get("/ns/sec/log", ok), 302)
	expect(t, e.do(req{method: "POST", path: "/edge-grants", bearer: ok}), 200)
	expectCode(t, e.get("/r/sec/x", narrowed(t, mint("user:r", "read"), map[string]any{"rules": []any{map[string]any{"not": slowP(4)}}})), 404, "not_found")

	// Each read has its own budget: a rule that runs out for one name
	// leaves the reads of another alone, as often as they are made.
	onX := narrowed(t, mint("user:r", "read"), map[string]any{"rules": []any{map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/resource", "value": "x"}},
		"then": []any{map[string]any{"op": "test", "path": "/resource", "schema": doubling(30)}}}}})
	for i := 0; i < 3; i++ {
		expectCode(t, e.get("/r/sec/x", onX), 404, "not_found")
		expect(t, e.get("/r/sec/y", onX), 302)
	}
}

// §6.6 Validation work: "each … key request" has one budget, however
// many resources it names. A grant whose rule takes more than half the
// budget for a name gets past the read check for either name alone (the
// namespace isn't sealed: 404 not_offered), and is 403 for both at once.
func TestV086KeyRequestOneBudget(t *testing.T) {
	t.Parallel()
	f, mint := stepOneFixture(t)
	e := f.tenv
	who := narrowed(t, mint("user:k", "read"), map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"x", "y"}}},
		map[string]any{"op": "test", "path": "/principal", "schema": doubling(9)}}})
	for _, name := range []string{"x", "y"} {
		_, r := e.keysOf("sec", map[string]any{"resources": []any{name}}, who)
		expectCode(t, r, 404, "not_offered")
	}
	_, r := e.keysOf("sec", map[string]any{"resources": []any{"x", "y"}}, who)
	expectCode(t, r, 403, "forbidden")
}

// §6.6 Validation work, §B.11.9 Edge grants: an exchange whose budget is
// spent fails as a whole. A grant of a covered namespace whose only role
// runs out on the check of unrestricted read gets no cookie for its
// subject set either: 403, nothing set.
func TestV086FilteredExchangeSpent(t *testing.T) {
	t.Parallel()
	plain := newKey("plain")
	role := func(levels int) map[string]any {
		return map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/principal", "schema": doubling(levels)}}}
	}
	w := newV75s(t, v75sOpts{env: []envOpt{func(o *core.Options) { o.MaxValidationSteps = 3000 }}, matches: func(doc map[string]any) {
		doc["keys"] = append(doc["keys"].([]any), plain.entry("read"))
		doc["roles"].(map[string]any)["slow"] = role(30)
		doc["roles"].(map[string]any)["quick"] = role(4)
	}})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	with := func(r string) string {
		return w.grant(plain, "user:li", []string{"matches"}, nil, map[string]any{"roles": []any{r}, "groups": []any{"editors"},
			"exp": w.clock.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	}
	r := w.do(req{method: "POST", path: "/edge-grants", bearer: with("slow")})
	expectCode(t, r, 403, "forbidden")
	if r.H.Get("Set-Cookie") != "" {
		t.Fatalf("the exchange set %q", r.H.Get("Set-Cookie"))
	}
	// Within the budget the same shape is exchanged.
	expect(t, w.do(req{method: "POST", path: "/edge-grants", bearer: with("quick")}), 200)
}
