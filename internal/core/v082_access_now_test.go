package core

import (
	"context"
	"slices"
	"testing"
)

// V82-02 (v0.82), ACC-3: unrestricted read needs, for a grant with roles,
// an effective role that lists read with no rule referring to /resource
// or /now (SPEC §2.1 Unrestricted read).

// §2.1 Unrestricted read: "if it carries roles, at least one effective
// role that lists read has no rule referring to /resource or /now".
// unrestrictedRoles leaves out a role with a rule on /now itself, the
// whole envelope included, so no caller can take one for a role that
// reads unrestricted; before v0.82 it returned such a role and relied on
// each caller evaluating a read envelope.
func TestV082AccessUnrestrictedRolesNow(t *testing.T) {
	t.Parallel()
	now := map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}
	whole := map[string]any{"op": "test", "path": "", "schema": map[string]any{"type": "object"}}
	prefixed := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^pub-"}}
	groups := map[string]any{"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "editors"}}}
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) {
		roles := doc["roles"].(map[string]any)
		roles["clock"] = map[string]any{"can": []any{"read"}, "rules": []any{now}}
		roles["envelope"] = map[string]any{"can": []any{"read"}, "rules": []any{whole}}
		roles["prefixed"] = map[string]any{"can": []any{"read"}, "rules": []any{prefixed}}
		roles["editors"] = map[string]any{"can": []any{"read", "branch"}, "rules": []any{groups}}
		roles["reader"] = map[string]any{"can": []any{"read", "branch"}}
		roles["brancher"] = map[string]any{"can": []any{"branch"}}
	}})
	w.seed()
	ctx := context.Background()
	for _, c := range []struct {
		roles []any
		want  []string
		reads bool
	}{
		{[]any{"clock"}, nil, false},
		{[]any{"envelope"}, nil, false},
		{[]any{"clock", "prefixed"}, nil, false},
		{[]any{"clock", "envelope", "prefixed"}, nil, false},
		// Conformance 131's /now half: a rule on /principal/groups
		// refers neither to /now nor to /resource, so its role counts.
		{[]any{"clock", "editors"}, []string{"editors"}, true},
		{[]any{"reader", "clock"}, []string{"reader"}, true},
	} {
		g := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:r", "groups": []any{"editors"}, "ns": []any{"matches", "matches-r7"},
			"can": []any{"read", "branch"}, "roles": append([]any{"brancher"}, c.roles...)})
		w.inTx(func(t2 *tx) {
			n := t2.nsByName("matches")
			cfg := t2.config(n.configSeq)
			a, err := t2.authenticate("matches", n, cfg, g, nil)
			if err != nil {
				t.Fatalf("%v: %v", c.roles, err)
			}
			got, ok := a.unrestrictedRoles()
			slices.Sort(got)
			if ok != (len(c.want) > 0) || !slices.Equal(got, c.want) {
				t.Errorf("roles %v: unrestrictedRoles %v %v, want %v", c.roles, got, ok, c.want)
			}
			if r := t2.readsNS(n, cfg, a, false); r != c.reads {
				t.Errorf("roles %v: readsNS %v, want %v", c.roles, r, c.reads)
			}
			if r := t2.readsNS(n, cfg, a, true); r != c.reads {
				t.Errorf("roles %v: readsNS at step 1 %v, want %v", c.roles, r, c.reads)
			}
			if r := t2.readsUnrestricted(a); r != c.reads {
				t.Errorf("roles %v: readsUnrestricted %v, want %v", c.roles, r, c.reads)
			}
		})
		// Branching checks unrestricted read of its base (§7.6, §C.2).
		_, err := w.e.CreateBranch(ctx, Request{NS: "matches", Cred: g}, BranchRequest{Name: "matches-r7", IfNoneMatch: true})
		if st := v75Status(err); c.reads && st == 403 || !c.reads && st != 403 {
			t.Errorf("roles %v: branching %v, want 403: %v", c.roles, err, !c.reads)
		}
	}
}

// §E.2.3 at E3, §C.2 item 5: keysReadScope refuses a grant none of whose
// roles that count for read passes, the roles with a rule on /now, which
// unrestrictedRoles now leaves out, not counting among those that might
// pass per resource.
func TestV082AccessKeysReadScopeNow(t *testing.T) {
	t.Parallel()
	now := map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}
	chiefs := map[string]any{"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "chiefs"}}}
	prefixed := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^pub-"}}
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) {
		roles := doc["roles"].(map[string]any)
		roles["clock"] = map[string]any{"can": []any{"read"}, "rules": []any{now}}
		roles["chiefs"] = map[string]any{"can": []any{"read"}, "rules": []any{chiefs}}
		roles["prefixed"] = map[string]any{"can": []any{"read"}, "rules": []any{prefixed}}
	}})
	for _, c := range []struct {
		roles                []any
		perResource, refused bool
	}{
		{[]any{"reader"}, false, false},
		{[]any{"chiefs"}, false, true},          // its rule fails for user:r
		{[]any{"clock", "chiefs"}, false, true}, // clock never passes, chiefs fails
		{[]any{"clock", "prefixed"}, true, false},
		{[]any{"chiefs", "prefixed"}, true, false},
	} {
		g := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:r", "groups": []any{"editors"}, "ns": []any{"matches"}, "can": []any{"read"}, "roles": c.roles})
		w.inTx(func(t2 *tx) {
			n := t2.nsByName("matches")
			a, err := t2.authenticate("matches", n, t2.config(n.configSeq), g, nil)
			if err != nil {
				t.Fatalf("%v: %v", c.roles, err)
			}
			if per, refused := t2.keysReadScope(a); per != c.perResource || refused != c.refused {
				t.Errorf("roles %v: keysReadScope per-resource %v, refused %v; want %v, %v", c.roles, per, refused, c.perResource, c.refused)
			}
		})
	}
}
