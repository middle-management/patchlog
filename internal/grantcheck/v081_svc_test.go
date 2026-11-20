package grantcheck_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

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
