package core

import (
	"context"
	"reflect"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// GET /ns/{ns}/principal gives the effective roles only, each { name,
// can, rules } as the configuration of X-Config-Revision defines it,
// rules [] if none; principal.roles in the envelope stays the names
// (§7.4, §6.4.1, v0.75; conformance scenario 64).
func TestV075PrincipalRolesAreObjects(t *testing.T) {
	rule := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": "^i18n-"}}
	e := v073Engine(t, DefaultLimits(), DefaultMaximums(), map[string]any{"read": "grant", "roles": map[string]any{
		"translator": map[string]any{"can": []any{"read", "append"}, "rules": []any{rule}},
		"reader":     map[string]any{"can": []any{"read"}}}})
	ctx := context.Background()
	g := e.mint(map[string]any{"kid": "k", "sub": "user:t", "ns": []any{"n"}, "roles": []any{"translator", "ghost", "reader"}})
	p, err := e.Principal(ctx, "n", Credentials{Bearer: g})
	if err != nil {
		t.Fatal(err)
	}
	want := []any{
		map[string]any{"name": "translator", "can": []any{"read", "append"}, "rules": []any{jsonv.FromGo(rule)}},
		map[string]any{"name": "reader", "can": []any{"read"}, "rules": []any{}},
	}
	if got := jsonv.FromGo(p.Body["roles"]); !reflect.DeepEqual(got, jsonv.FromGo(want)) {
		t.Fatalf("roles %v, want %v", got, want)
	}
	env, _ := p.Body["principal"].(map[string]any)
	if got := jsonv.FromGo(env["roles"]); !reflect.DeepEqual(got, []any{"translator", "reader"}) {
		t.Fatalf("principal.roles %v", got)
	}
	// The answer is a copy: changing it leaves the configuration alone.
	p.Body["roles"].([]any)[0].(map[string]any)["rules"].([]any)[0] = "x"
	p2, err := e.Principal(ctx, "n", Credentials{Bearer: g})
	if err != nil {
		t.Fatal(err)
	}
	if got := jsonv.FromGo(p2.Body["roles"]); !reflect.DeepEqual(got, jsonv.FromGo(want)) {
		t.Fatalf("roles after change %v", got)
	}

	// Without roles, and for an operator grant, roles is [].
	plain := e.mint(map[string]any{"kid": "k", "sub": "user:p", "ns": []any{"n"}, "can": []any{"read"}})
	op := e.opMint(map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"n"}, "can": []any{"config"}, "roles": []any{"reader"}})
	for name, b := range map[string]string{"plain": plain, "operator": op} {
		p, err := e.Principal(ctx, "n", Credentials{Bearer: b})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r, ok := p.Body["roles"].([]any); !ok || len(r) != 0 {
			t.Fatalf("%s roles %v", name, p.Body["roles"])
		}
	}
}
