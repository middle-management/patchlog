package server

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
)

// slowName is a step-1 rule, on /resource alone, whose schema test takes
// more than 2^30 steps: scenario 88's "schema of 30 nested levels, each
// applying the next twice".
func slowName() map[string]any {
	return map[string]any{"op": "test", "path": "/resource", "schema": doubling(30)}
}

// stepOneFixture is a namespace with small principal and namespace
// buckets, and a mint for root grants of its issuer.
func stepOneFixture(t *testing.T) (*authFixture, func(sub string, can ...string) *grant.Grant) {
	f := newAuthFixture(t, map[string]any{"limits": map[string]any{
		"ratePerPrincipal": map[string]any{"rate": 0.001, "burst": 2.0},
		"ratePerNamespace": map[string]any{"rate": 0.001, "burst": 3.0}}},
		func(o *core.Options) { o.MaxValidationSteps = 3000 })
	mint := func(sub string, can ...string) *grant.Grant {
		t.Helper()
		if can == nil {
			can = []string{"read", "create", "append", "restore", "config", "branch", "prune"}
		}
		g, err := grant.Mint(map[string]any{"kid": "issuer", "sub": sub, "ns": []any{"sec"}, "can": strs(can),
			"exp": f.tenv.clock.Now().Add(time.Hour).Format(time.RFC3339)}, f.issuer.priv)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	return f, mint
}

func expectSteps(t *testing.T, r *resp) {
	t.Helper()
	expectCode(t, r, 422, "limit")
	if r.Obj()["limit"] != "validationSteps" {
		t.Fatalf("limit %v: %s", r.Obj()["limit"], r.Body)
	}
}

// §6.2 step 1, §6.6 Validation work, GATE-2, LIM-7, conformance scenario
// 88: a write whose step-1 rules run out of validationSteps is 422 limit
// after the rate limits, drawing tokens only from buckets keyed by its
// principal, never the namespace's; with the principal's bucket empty it
// is 429, never 422.
func TestV086StepOneRunOut(t *testing.T) {
	t.Parallel()
	f, mint := stepOneFixture(t)
	e := f.tenv
	slow := narrowed(t, mint("user:w"), map[string]any{"rules": []any{slowName()}})
	put := func(name, who string) *resp { return e.write("PATCH", "sec", name, "", addRoot(map[string]any{}), who) }

	// Two tokens in the principal's bucket: two 422s, then 429.
	expectSteps(t, put("a", slow))
	expectSteps(t, put("b", slow))
	r := put("c", slow)
	expectCode(t, r, 429, "rate")
	if r.Obj()["limit"] != "ratePerPrincipal" || r.H.Get("Retry-After") == "" {
		t.Fatalf("429: %s", r.Body)
	}
	// A grant of that principal without the rule finds the bucket empty.
	expectCode(t, put("c", mint("user:w").Encode()), 429, "rate")

	// The namespace's bucket was never drawn on: its three tokens are all
	// there for other principals.
	amy, cat := mint("user:amy").Encode(), mint("user:cat").Encode()
	expect(t, put("d", amy), 201)
	expect(t, put("e", amy), 201)
	expect(t, put("f", cat), 201)
	r = put("g", cat)
	expectCode(t, r, 429, "rate")
	if r.Obj()["limit"] != "ratePerNamespace" {
		t.Fatalf("429: %s", r.Body)
	}
}

// Scenario 88, second half: where another step-1 check fails outright,
// such as a verb or a rule, that 403 answers and no token is drawn,
// whichever of the two is evaluated first.
func TestV086StepOneOutrightFirst(t *testing.T) {
	t.Parallel()
	f, mint := stepOneFixture(t)
	e := f.tenv
	put := func(name, who string) *resp { return e.write("PATCH", "sec", name, "", addRoot(map[string]any{}), who) }
	onlyX := map[string]any{"op": "test", "path": "/resource", "value": "x"}

	// A rule that fails after the one that ran out, and in a later block.
	after := narrowed(t, mint("user:w"), map[string]any{"rules": []any{slowName(), onlyX}})
	g, err := mint("user:w").Narrow(map[string]any{"rules": []any{slowName()}})
	if err != nil {
		t.Fatal(err)
	}
	later := narrowed(t, g, map[string]any{"rules": []any{onlyX}})
	// The verb: a grant that can't create, with the rule.
	noVerb := narrowed(t, mint("user:w", "read", "append"), map[string]any{"rules": []any{slowName()}})
	// A role whose rule fails outright, the only one that lists create.
	roleDoc := map[string]any{"picky": map[string]any{"can": []any{"read", "create"}, "rules": []any{slowName(), onlyX}}}
	expect(t, e.patchNS("sec", ops(op("add", "/roles/picky", roleDoc["picky"])), f.adminG), 201)
	role, err := grant.Mint(map[string]any{"kid": "issuer", "sub": "user:w", "ns": []any{"sec"}, "roles": []any{"picky"},
		"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}, f.issuer.priv)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		for _, who := range []string{after, later, noVerb, role.Encode()} {
			expectCode(t, put("y", who), 403, "forbidden")
		}
	}
	// Nothing was drawn by the twelve: the principal's two tokens are
	// there, and the same grants run out where no rule fails outright.
	expectSteps(t, put("x", after))
	expectSteps(t, put("x", role.Encode()))
	expectCode(t, put("x", later), 429, "rate")
}

// Scenario 88, last sentence, §7.5: in a batch an item whose step-1 rules
// ran out counts as failing authorisation. With no item failing outright
// the batch is 422 after the rate limits, drawing a token per item from
// the principal's bucket and none from the namespace's; with one failing
// outright the batch takes its status, lists both, and draws nothing. A
// dry run answers and draws as the submit.
func TestV086StepOneRunOutBatch(t *testing.T) {
	t.Parallel()
	f, mint := stepOneFixture(t)
	e := f.tenv
	// Names that start with slow run out; the name bad fails outright.
	rs := []any{
		map[string]any{"if": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^slow"}}},
			"then": []any{slowName()}},
		map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "bad"}},
	}
	who := narrowed(t, mint("user:w"), map[string]any{"rules": rs})
	item := func(name string) map[string]any {
		return map[string]any{"resource": name, "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}
	}
	batch := func(dry bool, names ...string) *resp {
		var items []any
		for _, n := range names {
			items = append(items, item(n))
		}
		path := "/ns/sec/batch"
		if dry {
			path += "?dry-run=1"
		}
		return e.do(req{method: "POST", path: path, bearer: who, body: map[string]any{"items": items}})
	}
	failed := func(r *resp) map[float64]map[string]any {
		t.Helper()
		out := map[float64]map[string]any{}
		for _, it := range r.Obj()["items"].([]any) {
			m := it.(map[string]any)
			out[m["index"].(float64)] = m
		}
		return out
	}

	// Mixed, submit and dry run, as often as one likes: 403, both items
	// listed, the one that passes not, and no token drawn.
	for i := 0; i < 3; i++ {
		for _, dry := range []bool{false, true} {
			r := batch(dry, "slow1", "fine", "bad")
			expectCode(t, r, 403, "batch")
			fs := failed(r)
			if len(fs) != 2 || fs[0]["status"] != 422.0 || fs[0]["code"] != "limit" || fs[0]["limit"] != "validationSteps" ||
				fs[2]["status"] != 403.0 || fs[2]["code"] != "forbidden" {
				t.Fatalf("mixed (dry %v): %s", dry, r.Body)
			}
		}
	}

	// Only a run-out: 422 for the batch, the item listed, one token of
	// the principal's two for its one item... and a dry run the other.
	r := batch(false, "slow1")
	expectCode(t, r, 422, "batch")
	if fs := failed(r); len(fs) != 1 || fs[0]["status"] != 422.0 || fs[0]["code"] != "limit" {
		t.Fatalf("run-out: %s", r.Body)
	}
	expectCode(t, batch(true, "slow2"), 422, "batch")
	expectCode(t, batch(false, "slow3"), 429, "rate")
	expectCode(t, batch(true, "slow3"), 429, "rate")

	// The namespace's bucket still holds its three tokens.
	amy, cat := mint("user:amy").Encode(), mint("user:cat").Encode()
	put := func(name, who string) *resp { return e.write("PATCH", "sec", name, "", addRoot(map[string]any{}), who) }
	expect(t, put("d", amy), 201)
	expect(t, put("e", amy), 201)
	expect(t, put("f", cat), 201)
	expectCode(t, put("g", cat), 429, "rate")
}

// §7.8 check 1, LIM-7, note on uploads: a blob upload whose step-1 rules
// run out of validationSteps is 422 limit after the rate limits, which
// come first: 429 once the principal's bucket is empty. So are a config
// write, a branch creation and a prune; a branch creation that also lacks
// unrestricted read is 403 and draws nothing.
func TestV086StepOneRunOutOtherWrites(t *testing.T) {
	t.Parallel()
	f, mint := stepOneFixture(t)
	e := f.tenv
	slow := map[string]any{"rules": []any{slowName()}}
	upload := func(sub string) *resp {
		r, _ := e.putBlob("sec", "pic", "image/png", "", []byte("png"), narrowed(t, mint(sub), slow))
		return r
	}
	expectSteps(t, upload("user:up"))
	expectSteps(t, upload("user:up"))
	expectCode(t, upload("user:up"), 429, "rate")

	// The rule for the others doesn't look at /resource, which a config
	// write has none of: a principal test that runs out.
	slowP := map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/principal", "schema": doubling(30)}}}
	cfgWrite := func(sub string) *resp {
		who := narrowed(t, mint(sub), slowP)
		return e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: e.configID("sec", f.adminG), body: ops(op("add", "/x-note", "n")), bearer: who})
	}
	expectSteps(t, cfgWrite("user:cfg"))
	expectSteps(t, cfgWrite("user:cfg"))
	expectCode(t, cfgWrite("user:cfg"), 429, "rate")

	branch := func(g string) *resp {
		return e.do(req{method: "POST", path: "/ns/sec/branches", ifNoneMatch: "*", bearer: g, body: map[string]any{"name": "sec-b", "patches": []any{}}})
	}
	// (The read check of branching evaluates the same rule against the
	// read envelope, with a budget of its own: it runs out too, which is
	// 403, as for a grant that can't read. Scenario 92.)
	for i := 0; i < 3; i++ {
		expectCode(t, branch(narrowed(t, mint("user:br"), slowP)), 403, "forbidden")
	}
	// A rule that only writes run out on leaves the read check alone.
	slowW := map[string]any{"rules": []any{map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "branch"}},
		"then": []any{map[string]any{"op": "test", "path": "/principal", "schema": doubling(30)}}}}}
	expectSteps(t, branch(narrowed(t, mint("user:br"), slowW)))
	expectSteps(t, branch(narrowed(t, mint("user:br"), slowW)))
	expectCode(t, branch(narrowed(t, mint("user:br"), slowW)), 429, "rate")

	horizon := e.create("sec", "doc", map[string]any{}, f.adminG)
	prune := func(sub string) *resp {
		return e.do(req{method: "POST", path: "/r/sec/doc/prune", bearer: narrowed(t, mint(sub), slow), body: map[string]any{"horizon": horizon}})
	}
	expectSteps(t, prune("user:pr"))
	expectSteps(t, prune("user:pr"))
	expectCode(t, prune("user:pr"), 429, "rate")
}
