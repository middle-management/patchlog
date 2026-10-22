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
