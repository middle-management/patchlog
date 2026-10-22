package grant

import (
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
)

// A grant carries roles when any block lists roles (§2.1, v0.66): a
// narrowing block listing roles over a root without them leaves no
// effective role, so the grant allows no verb, however many its root's
// can lists.
func TestV073RolesFromAnyBlock(t *testing.T) {
	f := newFixture(t, nil)
	n, err := mustMint(t, f, nil).Narrow(map[string]any{"via": "svc:x", "roles": []string{"reader"}})
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(roundtrip(t, n), f.env())
	if err != nil {
		t.Fatal(err)
	}
	if !v.HasRoles() || v.EffectiveRoles == nil || len(v.EffectiveRoles) != 0 {
		t.Fatalf("carries roles %v, effective %#v", v.HasRoles(), v.EffectiveRoles)
	}
	for _, verb := range []string{"read", "append"} {
		if ok, _ := v.Allows(verb); ok || v.Can[verb] {
			t.Fatalf("%s allowed without an effective role", verb)
		}
	}
	if len(v.Principal.Envelope()["roles"].([]any)) != 0 {
		t.Fatal("principal roles")
	}

	// A root listing roles keeps those every roles-listing block keeps.
	g := mustMint(t, f, map[string]any{"can": nil, "roles": []string{"reader", "editor"}})
	n, _ = g.Narrow(map[string]any{"roles": []string{"reader", "ghost"}})
	n, _ = n.Narrow(map[string]any{"via": "svc:y"})
	v, err = Verify(roundtrip(t, n), f.env())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(v.EffectiveRoles, ",") != "reader" || !v.Can["read"] || v.Can["append"] {
		t.Fatalf("effective %v, can %v", v.EffectiveRoles, v.Can)
	}

	// A grant without roles in any block allows its can.
	v, err = Verify(roundtrip(t, mustMint(t, f, nil)), f.env())
	if err != nil || v.HasRoles() || v.EffectiveRoles != nil {
		t.Fatalf("no roles: %v %v", err, v.EffectiveRoles)
	}
	if ok, roles := v.Allows("append"); !ok || roles != nil {
		t.Fatal("append without roles")
	}
}

// Only the root block's can is held to the key's can (§C.4, v0.65): a
// narrowing block's verbs outside it narrow nothing more (§C.1).
func TestV073NarrowingCanOutsideKey(t *testing.T) {
	f := newFixture(t, map[string]any{"can": []any{"read", "append"}})
	n, err := mustMint(t, f, nil).Narrow(map[string]any{"can": []string{"read", "delete"}})
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(roundtrip(t, n), f.env())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Can["read"] || v.Can["delete"] || v.Can["append"] || len(v.Can) != 1 {
		t.Fatalf("can %v", v.Can)
	}
	_, err = Verify(roundtrip(t, mustMint(t, f, map[string]any{"can": []string{"read", "delete"}})), f.env())
	wantStatus(t, err, 403)
}

// "*" in ns is for operator grants only, and any other grant naming it is
// invalid (401), whichever block names it, before the key scope's 403
// (§C.4, v0.63).
func TestV073StarIsUnauthenticated(t *testing.T) {
	f := newFixture(t, map[string]any{"can": []any{"read"}})
	n, err := mustMint(t, f, map[string]any{"can": []string{"read"}}).Narrow(map[string]any{"ns": []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(roundtrip(t, n), f.env())
	wantStatus(t, err, 401)
	// The key's can would refuse append (403); "*" is refused first.
	_, err = Verify(roundtrip(t, mustMint(t, f, map[string]any{"ns": []string{"*"}})), f.env())
	wantStatus(t, err, 401)
	env := f.env()
	env.Operator = true
	v, err := Verify(roundtrip(t, n), env)
	if err != nil || !v.Operator {
		t.Fatalf("operator grant naming *: %v", err)
	}
}

// Verified.Operator says an operator key verified the grant (§C.4, §7.4).
func TestV073VerifiedOperator(t *testing.T) {
	f := newFixture(t, nil)
	g := roundtrip(t, mustMint(t, f, nil))
	v, err := Verify(g, f.env())
	if err != nil || v.Operator {
		t.Fatalf("namespace grant: %v, operator %v", err, v != nil && v.Operator)
	}
	env := f.env()
	env.Operator = true
	if v, err = Verify(g, env); err != nil || !v.Operator {
		t.Fatalf("operator grant: %v", err)
	}
}

// maxTtl bounds the root block's remaining lifetime, exp − max(now, nbf)
// of the root alone (§C.4, v0.65): a narrowing block's earlier exp doesn't
// make an over-long root pass.
func TestV073MaxTTLOnRoot(t *testing.T) {
	f := newFixture(t, map[string]any{"maxTtl": "PT10M"})
	long := mustMint(t, f, map[string]any{"exp": ts(time.Hour)})
	n, err := long.Narrow(map[string]any{"exp": ts(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(roundtrip(t, n), f.env())
	wantStatus(t, err, 403)
	n, _ = mustMint(t, f, map[string]any{"exp": ts(9 * time.Minute)}).Narrow(map[string]any{"exp": ts(5 * time.Minute)})
	if _, err := Verify(roundtrip(t, n), f.env()); err != nil {
		t.Fatal(err)
	}
	// A narrowing block's later nbf doesn't shorten it either.
	n, _ = mustMint(t, f, map[string]any{"exp": ts(15 * time.Minute)}).Narrow(map[string]any{"nbf": ts(-time.Minute), "exp": ts(5 * time.Minute)})
	_, err = Verify(roundtrip(t, n), f.env())
	wantStatus(t, err, 403)
}

// requireAt dates a grant's issuance by the later of its root nbf and exp
// − maxTtl, of those that exist; with neither the grant fails the scope
// (§C.4, v0.65), and at is never looked up.
func TestV073RequireAtNeedsIssuance(t *testing.T) {
	at := "1" + strings.Repeat("a", 32)
	f := newFixture(t, map[string]any{"requireAt": true})
	env := f.env()
	var issuedAt []time.Time
	env.CheckAt = func(_, _ any, issued time.Time, _ *time.Duration) error {
		issuedAt = append(issuedAt, issued)
		return nil
	}
	_, err := Verify(roundtrip(t, mustMint(t, f, map[string]any{"at": at})), env)
	wantStatus(t, err, 403)
	if len(issuedAt) != 0 {
		t.Fatal("at checked against a made-up issuance")
	}
	nbf := now.Add(-time.Minute).Truncate(time.Second)
	if _, err := Verify(roundtrip(t, mustMint(t, f, map[string]any{"at": at, "nbf": ts(-time.Minute)})), env); err != nil {
		t.Fatal(err)
	}
	if len(issuedAt) != 1 || !issuedAt[0].Equal(nbf) {
		t.Fatalf("issued %v, want the root's nbf %v", issuedAt, nbf)
	}
	// A key maxTtl dates it too: exp − maxTtl.
	f = newFixture(t, map[string]any{"requireAt": true, "maxTtl": "PT2H"})
	env.Keys = f.keys
	if _, err := Verify(roundtrip(t, mustMint(t, f, map[string]any{"at": at})), env); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(-time.Hour); len(issuedAt) != 2 || !issuedAt[1].Equal(want) {
		t.Fatalf("issued %v, want exp − maxTtl %v", issuedAt, want)
	}
}

// A root block's revocation id is its grant id (§C.4, v0.71): revoking it
// revokes every token minted with that root block. A narrowing block's is
// over its signature, and the root's signature id, its revocation id
// before, still revokes it.
func TestV073RevocationByGrantID(t *testing.T) {
	f := newFixture(t, nil)
	a, b := mustMint(t, f, nil), mustMint(t, f, nil)
	if a.ID() != b.ID() || a.rootSigID() == b.rootSigID() {
		t.Fatal("two tokens of one root block")
	}
	n, _ := a.Narrow(map[string]any{"via": "svc:x"})
	env := f.env()
	env.Revoked = map[string]bool{a.ID().String(): true}
	for _, g := range []*Grant{a, b, n} {
		_, err := Verify(roundtrip(t, g), env)
		wantStatus(t, err, 401)
	}
	env.Revoked = map[string]bool{a.rootSigID(): true}
	_, err := Verify(roundtrip(t, n), env)
	wantStatus(t, err, 401)
	if _, err := Verify(roundtrip(t, b), env); err != nil {
		t.Fatal("an old-form id revokes only the token it names")
	}
	narrowing := ids.Of(n.c.blocks[1].sig).String()
	env.Revoked = map[string]bool{narrowing: true}
	_, err = Verify(roundtrip(t, n), env)
	wantStatus(t, err, 401)
	if _, err := Verify(roundtrip(t, a), env); err != nil {
		t.Fatal(err)
	}
	if r := n.RevocationIDs(); len(r) != 2 || r[0] != a.ID().String() || r[1] != narrowing {
		t.Fatalf("revocation ids %v", r)
	}
}
