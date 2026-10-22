package core

import (
	"context"
	"testing"
)

// P25 GATE-RULE-ORDER: step 6 of §6.2 runs the *-key guard, a config
// write's in_use refusals, grant, key and role rules (403), then namespace
// rules (422), each for every item of a batch before the next; at E3 a
// rule fails as a whole only when its outcome depends on what the server
// can't see.

// p25NSRule is a namespace rule that refuses a create, append, config,
// branch, purge or prune whose doc has no /ok (422 rule).
var p25NSRule = map[string]any{
	"if":   []any{map[string]any{"op": "test", "path": "/action", "schema": map[string]any{"enum": []any{"create", "append", "config", "branch", "purge", "prune"}}}},
	"then": []any{map[string]any{"op": "test", "path": "/doc/ok", "exists": true}},
}

// p25GrantRule is a block rule that refuses a write whose doc has no
// /granted: it refers to /doc, so step 6 decides it (403).
var p25GrantRule = map[string]any{"op": "test", "path": "/doc/granted", "exists": true}

func p25Root(v any) []any { return []any{map[string]any{"op": "add", "path": "", "value": v}} }

// p25Refused checks err is a refusal with status and code.
func p25Refused(t *testing.T, what string, err error, status int, code string) *Error {
	t.Helper()
	e, ok := err.(*Error)
	if !ok || e.Status != status || e.Body["code"] != code {
		t.Fatalf("%s: got %v, want %d %s", what, err, status, code)
	}
	return e
}

// p25Rule checks err is a namespace rule's 422 naming rule i at path.
func p25Rule(t *testing.T, what string, err error, i int, path string) {
	t.Helper()
	e := p25Refused(t, what, err, 422, "rule")
	if e.Body["rule"] != i || e.Body["path"] != path {
		t.Fatalf("%s: rule %v at %v, want %d at %s", what, e.Body["rule"], e.Body["path"], i, path)
	}
}

// GB-1 (GR-25): a write that fails both a grant rule and a namespace rule
// is 403, not 422, whatever writes it: a resource create or append, a
// config write, a branch's creation, a purge or a prune (§6.2 step 6,
// §6.4.3, §C.2 item 4).
func TestV073P25GrantRulesBeforeNamespaceRules(t *testing.T) {
	e := v073Engine(t, p17Fast(), p17Fast(), map[string]any{"read": "grant"})
	ctx := context.Background()
	var ks p17Keys
	ks.add("admin", map[string]any{"can": []any{"*"}})
	verbs := []any{"read", "create", "append", "purge", "config", "branch"}
	ks.add("w", map[string]any{"can": verbs})
	e.create("p", map[string]any{"read": "grant", "keys": ks.entries, "rules": []any{p25NSRule}})
	admin := ks.mint(t, map[string]any{"kid": "admin", "sub": "user:admin", "ns": []any{"p"}, "can": []any{"read", "create", "prune"}})
	both := ks.mint(t, map[string]any{"kid": "w", "sub": "user:w", "ns": []any{"p"}, "can": verbs, "rules": []any{p25GrantRule}})
	nsOnly := ks.mint(t, map[string]any{"kid": "w", "sub": "user:n", "ns": []any{"p"}, "can": verbs})
	// A prune without an archive needs a * key (§8.6), and isn't a config
	// write, so namespace rules judge it.
	adminBoth := ks.mint(t, map[string]any{"kid": "admin", "sub": "user:admin", "ns": []any{"p"}, "can": []any{"read", "prune"}, "rules": []any{p25GrantRule}})

	ok, err := e.WriteResource(ctx, Request{NS: "p", Cred: admin}, Item{Resource: "a", IfNoneMatch: true, Steps: []Step{{Patches: p25Root(map[string]any{"ok": true})}}})
	if err != nil {
		t.Fatal(err)
	}
	head := ok.Items[0].IDs[0]
	h, err := e.NamespaceHead(ctx, "p", admin)
	if err != nil {
		t.Fatal(err)
	}
	cfgID := h.Config
	type write = func(cred Credentials) error
	writes := map[string]write{
		"create": func(cred Credentials) error {
			_, err := e.WriteResource(ctx, Request{NS: "p", Cred: cred}, Item{Resource: "c", IfNoneMatch: true, Steps: []Step{{Patches: p25Root(map[string]any{})}}})
			return err
		},
		"append": func(cred Credentials) error {
			_, err := e.WriteResource(ctx, Request{NS: "p", Cred: cred}, Item{Resource: "a", IfMatch: head, Steps: []Step{{Patches: []any{map[string]any{"op": "remove", "path": "/ok"}}}}})
			return err
		},
		"config": func(cred Credentials) error {
			_, err := e.WriteConfig(ctx, Request{NS: "p", Cred: cred}, ConfigChange{IfMatch: cfgID, Patches: []any{map[string]any{"op": "add", "path": "/x-note", "value": 1.0}}})
			return err
		},
		"branch": func(cred Credentials) error {
			_, err := e.CreateBranch(ctx, Request{NS: "p", Cred: cred}, BranchRequest{Name: "pb", IfNoneMatch: true})
			return err
		},
		"purge": func(cred Credentials) error {
			_, err := e.Purge(ctx, Request{NS: "p", Cred: cred}, "a", head, false)
			return err
		},
	}
	for what, w := range writes {
		p25Refused(t, what+" failing both kinds of rule", w(both), 403, "forbidden")
		p25Rule(t, what+" failing a namespace rule only", w(nsOnly), 0, "/rules/0/then/0")
	}
	var prune write = func(cred Credentials) error {
		_, err := e.Prune(ctx, Request{NS: "p", Cred: cred}, "a", PruneRequest{Horizon: head})
		return err
	}
	p25Refused(t, "prune failing both kinds of rule", prune(adminBoth), 403, "forbidden")
	p25Rule(t, "prune failing a namespace rule only", prune(admin), 0, "/rules/0/then/0")
	// A write passing both is written.
	if _, err := e.WriteResource(ctx, Request{NS: "p", Cred: both}, Item{Resource: "d", IfNoneMatch: true,
		Steps: []Step{{Patches: p25Root(map[string]any{"ok": true, "granted": true})}}}); err != nil {
		t.Fatal(err)
	}
}

// GB-2 (GR-25): in a batch, the grant, key and role rules run for every
// item before the namespace rules run for any. The batch fails with the
// status of the earliest failing sub-step, reporting only the items that
// failed it; a dry run drops those and runs the next sub-step for the rest
// (§6.2 step 6, §7.5 Failure and Dry run).
func TestV073P25BatchRuleSubSteps(t *testing.T) {
	e := v073Engine(t, p17Fast(), p17Fast(), map[string]any{"read": "grant"})
	ctx := context.Background()
	var ks p17Keys
	ks.add("w", map[string]any{"can": []any{"read", "create", "append"}})
	e.create("p", map[string]any{"read": "grant", "keys": ks.entries, "rules": []any{p25NSRule}})
	// A block rule for documents of kind g only.
	kindG := map[string]any{"if": []any{map[string]any{"op": "test", "path": "/doc/kind", "value": "g"}}, "then": []any{p25GrantRule}}
	cred := ks.mint(t, map[string]any{"kid": "w", "sub": "user:w", "ns": []any{"p"}, "can": []any{"read", "create", "append"}, "rules": []any{kindG}})
	create := func(name string, steps ...[]any) Item {
		it := Item{Resource: name, IfNoneMatch: true}
		for _, s := range steps {
			it.Steps = append(it.Steps, Step{Patches: s})
		}
		return it
	}
	items := []Item{
		// A namespace rule refuses item 0, the grant rule item 1.
		create("n", p25Root(map[string]any{})),
		create("g", p25Root(map[string]any{"ok": true, "kind": "g"})),
		// Item 2's first step fails only the namespace rule, its second
		// only the grant rule: the grant rules run for both steps first.
		create("s", p25Root(map[string]any{}), []any{map[string]any{"op": "replace", "path": "", "value": map[string]any{"ok": true, "kind": "g"}}}),
	}
	_, err := e.Batch(ctx, Request{NS: "p", Cred: cred}, items, nil, nil, false)
	b := p25Refused(t, "batch", err, 403, "batch")
	got := b.Body["items"].([]any)
	if len(got) != 2 {
		t.Fatalf("batch reports %v, want items 1 and 2", got)
	}
	for k, want := range []int{1, 2} {
		m := got[k].(map[string]any)
		if m["index"] != want || m["status"] != 403 || m["code"] != "forbidden" {
			t.Fatalf("batch item %d: %v, want index %d at 403 forbidden", k, m, want)
		}
	}
	// Without the items the grant rule refuses, the namespace rule's 422.
	_, err = e.Batch(ctx, Request{NS: "p", Cred: cred}, items[:1], nil, nil, false)
	b = p25Refused(t, "batch of item 0", err, 422, "batch")
	if got := b.Body["items"].([]any); len(got) != 1 || got[0].(map[string]any)["index"] != 0 || got[0].(map[string]any)["path"] != "/rules/0/then/0" {
		t.Fatalf("batch of item 0 reports %v", got)
	}

	// A dry run reports each item at the sub-step it failed.
	res, err := e.Batch(ctx, Request{NS: "p", Cred: cred}, append(items, create("fine", p25Root(map[string]any{"ok": true}))), nil, nil, true)
	if err != nil || res.Status != 200 || len(res.Items) != 4 {
		t.Fatalf("dry run: %v %+v", err, res)
	}
	for i, want := range []struct {
		status int
		code   string
	}{{422, "rule"}, {403, "forbidden"}, {403, "forbidden"}, {201, ""}} {
		r := res.Items[i]
		if r.Status != want.status || (want.code != "" && r.Err["code"] != want.code) {
			t.Errorf("dry run item %d: %d %v, want %d %s", i, r.Status, r.Err, want.status, want.code)
		}
	}
}
