package grantcheck_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/rules"
)

// §C.2 item 5 (v0.78): a read envelope has no now, and a rule that refers
// to /now, at any depth, fails a read as a whole. A grant with one in its
// blocks or key scope is refused every read and doesn't read
// unrestricted; a role with one doesn't count for read.
func TestV081SvcReadNow(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	cfgID := must(f.adminC.NSHead(ctx, "sec")).Config
	// past passes against any envelope with a now after 2000, and against
	// one without: only failing it before Eval refuses it.
	past := map[string]any{"not": map[string]any{"op": "test", "path": "/now", "value": "2000-01-01T00:00:00.000Z"}}
	must(f.adminC.PatchConfig(ctx, "sec", cfgID, []any{
		map[string]any{"op": "add", "path": "/roles/clock", "value": map[string]any{"can": []any{"read"}, "rules": []any{past}}},
		map[string]any{"op": "add", "path": "/roles/whole", "value": map[string]any{"can": []any{"read"},
			"rules": []any{map[string]any{"op": "test", "path": "", "exists": true}}}},
	}))
	whole := map[string]any{"op": "test", "path": "", "exists": true}
	for _, c := range []struct {
		name               string
		can                []string
		extra              map[string]any
		reads, unres, wide bool
	}{
		{"block rule on /now", []string{"read"}, map[string]any{"rules": []any{past}}, false, false, false},
		{"block rule on the whole envelope", []string{"read"}, map[string]any{"rules": []any{whole}}, false, false, false},
		{"role on /now", nil, map[string]any{"roles": []any{"clock"}}, false, false, false},
		{"role on the whole envelope", nil, map[string]any{"roles": []any{"whole"}}, false, false, false},
		{"role on /now beside a reader", nil, map[string]any{"roles": []any{"clock", "reader"}}, true, true, true},
		{"role on /now beside prefixed", nil, map[string]any{"roles": []any{"clock", "prefixed"}}, false, false, false},
	} {
		tok := f.grant(f.issuer, "user:bob", []string{"sec"}, c.can, c.extra)
		v, err := f.ch.Verify(ctx, "sec", tok)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := f.ch.AllowsRead(v, "a"); got != c.reads {
			t.Errorf("%s: AllowsRead %v", c.name, got)
		}
		if got := f.ch.ReadsUnrestricted(v); got != c.unres {
			t.Errorf("%s: ReadsUnrestricted %v", c.name, got)
		}
		if got := f.ch.NamespaceWide(v); got != c.wide {
			t.Errorf("%s: NamespaceWide %v", c.name, got)
		}
		d, err := f.ch.CheckRead(ctx, "sec", tok, "a")
		if err != nil || d.Allowed != c.reads {
			t.Errorf("%s: CheckRead %+v %v", c.name, d, err)
		}
		// Refused by /now: each case but the reader beside a /now role
		// and prefixed beside one (which reads pub- names).
		wantRefused := !c.reads && c.name != "role on /now beside prefixed"
		if got := grantcheck.RefusedByNow(v); got != wantRefused {
			t.Errorf("%s: RefusedByNow %v", c.name, got)
		}
	}
	// The envelope itself carries no now.
	if env := grantcheck.ReadEnvelope(nil, "a", f.s.Now()); env["now"] != nil {
		t.Errorf("ReadEnvelope has now: %v", env)
	}
	// A rule refers to /now (or the whole envelope) at any depth.
	for _, c := range []struct {
		rule  map[string]any
		fails bool
	}{
		{past, true},
		{whole, true},
		{map[string]any{"any": []any{map[string]any{"op": "test", "path": "/action", "value": "read"}, past}}, true},
		{map[string]any{"op": "test", "path": "/resource", "value": "a"}, false},
	} {
		r, err := rules.Compile(c.rule)
		if err != nil {
			t.Fatal(err)
		}
		if got := grantcheck.FailsRead(r); got != c.fails {
			t.Errorf("FailsRead(%v) = %v", c.rule, got)
		}
	}
}

// §A.4 gs markers, §C.2 item 5: a role with a rule on /now doesn't count
// for read, so the scope marker and the filter leave it out and judge by
// the other roles (ScopeInputOf, FilterOf); a grant all of whose roles
// refer to /now reads nothing and has no marker (ReadsScope false), never
// the digest of a grant without roles. A key-scope or block rule on /now
// still gives no marker, and ScopeDigest still refuses a stored role that
// has gained one since, so that cookie ends.
func TestV081SvcScopeWithoutNowRoles(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	cfgID := must(f.adminC.NSHead(ctx, "sec")).Config
	clock := map[string]any{"op": "test", "path": "/now", "exists": true}
	must(f.adminC.PatchConfig(ctx, "sec", cfgID, []any{
		map[string]any{"op": "add", "path": "/roles/clock", "value": map[string]any{"can": []any{"read"}, "rules": []any{clock}}},
	}))
	verify := func(extra map[string]any) *grant.Verified {
		v, err := f.ch.Verify(ctx, "sec", f.grant(f.issuer, "user:bob", []string{"sec"}, nil, extra))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	both := verify(map[string]any{"roles": []any{"clock", "prefixed"}})
	only := verify(map[string]any{"roles": []any{"prefixed"}})
	in := grantcheck.ScopeInputOf(both)
	if _, ok := in.Roles["clock"]; ok || in.Roles["prefixed"] == nil {
		t.Fatalf("ScopeInputOf roles %v", in.Roles)
	}
	d1, ok1 := grantcheck.ReadsScope(both)
	d2, ok2 := grantcheck.ReadsScope(only)
	if !ok1 || !ok2 || d1 != d2 {
		t.Fatalf("ReadsScope with a /now role %q %v, without %q %v", d1, ok1, d2, ok2)
	}
	flt := grantcheck.FilterOf(both)
	if !flt.Allows("pub-a") || flt.Allows("a") || len(flt.Roles) != 1 {
		t.Fatalf("FilterOf: pub-a %v a %v roles %v", flt.Allows("pub-a"), flt.Allows("a"), flt.Roles)
	}

	clockOnly := verify(map[string]any{"roles": []any{"clock"}})
	if d, ok := grantcheck.ReadsScope(clockOnly); ok {
		t.Fatalf("ReadsScope of a grant whose only role refers to /now: %q", d)
	}
	if fl := grantcheck.FilterOf(clockOnly); fl.Allows("pub-a") || fl.Allows("a") {
		t.Fatal("FilterOf of a grant whose only role refers to /now allows")
	}
	none, err := f.ch.Verify(ctx, "sec", f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}))
	if err != nil {
		t.Fatal(err)
	}
	if dn, ok := grantcheck.ReadsScope(none); !ok || dn == "" {
		t.Fatalf("ReadsScope of a grant without roles %q %v", dn, ok)
	}

	// A stored role that gains a /now rule: its digest can't be made.
	in.Roles["prefixed"] = append(append([]any{}, in.Roles["prefixed"]...), clock)
	if _, ok := grantcheck.ScopeDigest(in); ok {
		t.Fatal("ScopeDigest with a role that refers to /now")
	}
	// A block rule on /now: no marker.
	blk, err := f.ch.Verify(ctx, "sec", f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{clock}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := grantcheck.ReadsScope(blk); ok {
		t.Fatal("ReadsScope with a block rule on /now")
	}
}

// A stored filter (index edge_filters, the origin's filtered_gs) that
// holds a rule on /now judges as the read check does: a key-scope or
// block rule refuses every read, and a role with one doesn't count, even
// inside a not, which would pass against an envelope without now.
func TestV081SvcDecodedFilterNow(t *testing.T) {
	past := map[string]any{"not": map[string]any{"op": "test", "path": "/now", "value": "2000-01-01T00:00:00.000Z"}}
	blk := &grantcheck.ReadFilter{BlockRules: []any{past}}
	g, err := grantcheck.DecodeReadFilter(blk.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if g.Allows("a") || g.AllowsItem("a") {
		t.Fatal("a block rule on /now allows")
	}
	key := &grantcheck.ReadFilter{KeyRules: []any{past}}
	if key.Allows("a") {
		t.Fatal("a key-scope rule on /now allows")
	}
	role := &grantcheck.ReadFilter{Roles: [][]any{{past}}}
	if role.Allows("a") || role.AllowsItem("a") {
		t.Fatal("a role on /now counts")
	}
	two := &grantcheck.ReadFilter{Roles: [][]any{{past}, {}}}
	if !two.Allows("a") || !two.AllowsItem("a") {
		t.Fatal("a role without /now beside one with it doesn't count")
	}
}
