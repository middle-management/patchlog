package grantcheck_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/grantcheck"
)

// v073Rules returns rules of n forms in all: one all of n-1 leaves.
func v073Rules(n int) []any {
	leaves := make([]any, n-1)
	for i := range leaves {
		leaves[i] = map[string]any{"op": "test", "path": "/action", "exists": true}
	}
	return []any{map[string]any{"all": leaves}}
}

// Services verify as the origin does (§C.6): a grant over rulesPerGrant,
// counting nested forms, or with a rule that doesn't compile, is refused
// when decoded, before its ns check (§C.8, §6.6). Until services answer
// the limit 413 (F-C3), the checker refuses it as no usable grant.
func TestV073DecodeLimitsAndRules(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	must(f.adminC.CreateDoc(ctx, "sec", "a", map[string]any{}))
	ok := f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"rules": v073Rules(32)})
	if _, err := f.ch.Verify(ctx, "sec", ok); err != nil {
		t.Fatal(err)
	}
	over := map[string]any{"rules": append(v073Rules(17), v073Rules(17)...)}
	for _, ns := range []string{"sec", "other"} {
		tok := f.grant(f.issuer, "user:bob", []string{ns}, []string{"read"}, over)
		if _, err := f.ch.Verify(ctx, "sec", tok); authStatus(err) != 401 {
			t.Fatalf("34 forms naming %s: %v", ns, err)
		}
		if _, err := f.ch.CheckRead(ctx, "sec", tok, "a"); authStatus(err) != 401 {
			t.Fatalf("34 forms naming %s, read: %v", ns, err)
		}
	}
	wide := grantcheck.New(f.s.Client(t), grantcheck.WithMaxGrantRules(40))
	if _, err := wide.Decode(f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, over)); err != nil {
		t.Fatalf("WithMaxGrantRules: %v", err)
	}
	bad := f.grant(f.issuer, "user:bob", []string{"other"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "frob"}}})
	if _, err := f.ch.Verify(ctx, "sec", bad); authStatus(err) != 401 {
		t.Fatalf("uncompilable rule: %v", err)
	}
}

// NamespaceWide is whether a grant would be issued a namespace-wide edge
// grant (§C.5.2, §B.11.5 g/all): unrestricted read, and no rule of its
// blocks or key scope, nor of the role it qualifies by, referring to /now.
func TestV073NamespaceWide(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	cfgID := must(f.adminC.NSHead(ctx, "sec")).Config
	must(f.adminC.PatchConfig(ctx, "sec", cfgID, []any{map[string]any{"op": "add", "path": "/roles/clock",
		"value": map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/now", "exists": true}}}}}))
	clock := map[string]any{"op": "test", "path": "/now", "exists": true}
	fixed := map[string]any{"op": "test", "path": "/resource", "value": "a"}
	for _, c := range []struct {
		name               string
		can                []string
		extra              map[string]any
		unrestricted, wide bool
	}{
		{"read", []string{"read"}, nil, true, true},
		// A rule on /now fails every read (§C.2 item 5, v0.78).
		{"block rule on /now", []string{"read"}, map[string]any{"rules": []any{clock}}, false, false},
		{"fixed resource", []string{"read"}, map[string]any{"rules": []any{fixed}}, false, false},
		{"reader role", nil, map[string]any{"roles": []any{"reader"}}, true, true},
		{"role on /now", nil, map[string]any{"roles": []any{"clock"}}, false, false},
		{"role on /now beside a qualifying one", nil, map[string]any{"roles": []any{"clock", "reader"}}, true, true},
		{"role on /resource", nil, map[string]any{"roles": []any{"prefixed"}}, false, false},
		{"no read", []string{"append"}, nil, false, false},
	} {
		v, err := f.ch.Verify(ctx, "sec", f.grant(f.issuer, "user:bob", []string{"sec"}, c.can, c.extra))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := f.ch.ReadsUnrestricted(v); got != c.unrestricted {
			t.Errorf("%s: ReadsUnrestricted %v", c.name, got)
		}
		if got := f.ch.NamespaceWide(v); got != c.wide {
			t.Errorf("%s: NamespaceWide %v", c.name, got)
		}
	}
}
