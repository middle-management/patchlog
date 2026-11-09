package grantcheck_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// v075Verified verifies a fixed grant: li, in editors and interns, with
// the reader role, signed by a key whose scope tests /resource by
// pattern, with a block rule on /principal/id. Its ReadsScope is the
// index's golden digest (TestV075ReadsScopeGolden).
func v075Verified(t *testing.T, blockRules []any) *grant.Verified {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	keys, err := grant.ParseKeys(jsonv.MustParse([]byte(`[{"kid":"cat-01","alg":"Ed25519","pub":"` + pub + `",
		"can":["read"],"rules":[{"op":"test","path":"/resource","schema":{"type":"string","pattern":"^m"}}]}]`)))
	if err != nil {
		t.Fatal(err)
	}
	roles, err := grant.ParseRoles(jsonv.MustParse([]byte(`{"reader":{"can":["read"],
		"rules":[{"op":"test","path":"/principal/groups","schema":{"contains":{"const":"editors"}}}]}}`)))
	if err != nil {
		t.Fatal(err)
	}
	root := map[string]any{"kid": "cat-01", "sub": "user:li", "groups": []any{"editors", "interns"}, "roles": []any{"reader"},
		"ns": []any{"matches"}, "can": []any{"read"}, "exp": "2030-01-01T00:00:00Z"}
	if blockRules != nil {
		root["rules"] = blockRules
	}
	g, err := grant.Mint(root, priv)
	if err != nil {
		t.Fatal(err)
	}
	v, err := grant.Verify(g, grant.Env{Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NS: "matches", Keys: keys, Roles: roles,
		Revoked: map[string]bool{}, ValidateAttrs: grantcheck.ValidateAttrs})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

var v075BlockRules = []any{map[string]any{"op": "test", "path": "/principal/id", "value": "user:li"}}

// §A.4, §B.11.9: ReadsScope is the index's scope digest byte for byte
// (the golden value is index.readsScope's for the same grant), and
// ScopeDigest over ScopeInputOf gives it again.
func TestV075ReadsScopeGolden(t *testing.T) {
	t.Parallel()
	const golden = "1mu5jofataofnnyjv47pgv4hbaomjfuo7" // index.readsScope of the same grant
	v := v075Verified(t, v075BlockRules)
	d, ok := grantcheck.ReadsScope(v)
	if !ok || d != golden {
		t.Fatalf("ReadsScope = %q, %v; want %s", d, ok, golden)
	}
	if d2, ok := grantcheck.ScopeDigest(grantcheck.ScopeInputOf(v)); !ok || d2 != d {
		t.Fatalf("ScopeDigest = %q, %v", d2, ok)
	}
	// The digest reads only the /principal values the rules refer to: a
	// change of groups the rules name changes it.
	in := grantcheck.ScopeInputOf(v)
	in.Principal = map[string]any{"id": "user:li", "groups": []any{"interns"}}
	if d3, ok := grantcheck.ScopeDigest(in); !ok || d3 == d {
		t.Fatalf("other groups: %q, %v", d3, ok)
	}
	// A rule on /now, or on the whole envelope, makes the namespace
	// unreadable this way.
	for _, p := range []string{"/now", ""} {
		vn := v075Verified(t, []any{map[string]any{"op": "test", "path": p, "exists": true}})
		if _, ok := grantcheck.ReadsScope(vn); ok {
			t.Errorf("a rule on %q: ReadsScope ok", p)
		}
	}
}

// §B.5: CombinedAt is I.8's combined checkpoint.
func TestV075CombinedAt(t *testing.T) {
	t.Parallel()
	const (
		nsID1 = "1vmctae4vewju6nvxi374rkrkmyzpdrif" // I.2's ns_id₁
		nsID2 = "1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm" // I.2's ns_id₂
		at    = "1vwnfnoyshruyx4lul4a25rtctooiph5v"
	)
	if got := grantcheck.CombinedAt(map[string]string{"cat": nsID1, "matches": nsID2}); got != at {
		t.Errorf("CombinedAt = %s, want %s (I.8)", got, at)
	}
}

// §B.11.9 item 2: ReadFilter judges a read as the grant's read check does
// (Allows, the index's semantics), and AllowsItem counts a role only if
// its rules refer to nothing in /principal but groups and roles. Encode
// and DecodeReadFilter round-trip.
func TestV075ReadFilter(t *testing.T) {
	t.Parallel()
	v := v075Verified(t, nil)
	f := grantcheck.FilterOf(v)
	if !f.Allows("match1") || f.Allows("derby") || !f.AllowsItem("match1") || f.AllowsItem("derby") {
		t.Fatalf("key-scope pattern: Allows %v %v, AllowsItem %v %v", f.Allows("match1"), f.Allows("derby"), f.AllowsItem("match1"), f.AllowsItem("derby"))
	}
	g, err := grantcheck.DecodeReadFilter(f.Encode())
	if err != nil || g.Encode() != f.Encode() || !g.Allows("match1") || g.Allows("derby") {
		t.Fatalf("round trip: %v %s", err, g.Encode())
	}
	// A role with a /principal/id rule allows for the read check, never
	// for item 2.
	sub := &grantcheck.ReadFilter{Roles: [][]any{{map[string]any{"op": "test", "path": "/principal/id", "value": "user:li"}}},
		Principal: map[string]any{"id": "user:li", "groups": []any{}}}
	if !sub.Allows("m") || sub.AllowsItem("m") {
		t.Fatalf("sub role: Allows %v AllowsItem %v", sub.Allows("m"), sub.AllowsItem("m"))
	}
	// Roles carried, none listing read: nothing.
	none := &grantcheck.ReadFilter{Roles: [][]any{}}
	if none.Allows("m") || none.AllowsItem("m") {
		t.Fatal("no role allows")
	}
	// No roles: blocks and key scope alone.
	if !(&grantcheck.ReadFilter{}).AllowsItem("m") {
		t.Fatal("no roles carried")
	}
}
