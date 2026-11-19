package server

import (
	"testing"
	"time"

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
