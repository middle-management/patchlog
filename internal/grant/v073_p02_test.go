package grant

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/rules"
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

// The stored form is the authority block alone, a SignedBlock (§C.3, §C.8,
// v0.63). Rows stored before, whole chains without proof, still read, as
// their authority block.
func TestV073StoredAuthorityBlock(t *testing.T) {
	f := newFixture(t, nil)
	n, _ := mustMint(t, f, nil).Narrow(map[string]any{"via": "svc:x", "rules": []any{map[string]any{"op": "test", "path": "/action", "value": "read"}}})
	s := n.Stored()
	if string(s) != string(n.c.blocks[0].encode()) || strings.Contains(string(s), "svc:x") {
		t.Fatal("the stored form is the authority SignedBlock")
	}
	for _, parse := range []func([]byte) (*Grant, error){ParseStoredBlock, ParseStored} {
		p, err := parse(s)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Blocks) != 1 || p.ID() != n.ID() || p.HasProof() || !p.SignedBy(f.keys[0].Pub) {
			t.Fatal("stored authority block")
		}
		if sb := p.SignedBlocks(); len(sb) != 1 || string(sb[0]) != string(s) {
			t.Fatal("signed blocks of the stored form")
		}
	}
	legacy := (&container{blocks: n.c.blocks}).encode()
	if _, err := ParseStoredBlock(legacy); err == nil {
		t.Fatal("a whole chain parsed as one SignedBlock")
	}
	p, err := ParseStored(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Blocks) != 1 || p.ID() != n.ID() || string(p.Stored()) != string(s) || !p.SignedBy(f.keys[0].Pub) {
		t.Fatal("a legacy row reads as its authority block")
	}
	// Neither a token nor a SignedBlock that isn't a root block is stored.
	if _, err := ParseStored(tokenBytes(t, n.Encode())); err == nil {
		t.Fatal("token accepted as stored form")
	}
	_, err = ParseStoredBlock(n.c.blocks[1].encode())
	wantStatus(t, err, 401)
}

// "*" in a block's can makes the grant invalid (§C.1, v0.66), a narrowing
// block's too.
func TestV073StarCanInNarrowingBlock(t *testing.T) {
	f := newFixture(t, nil)
	n, err := mustMint(t, f, nil).NarrowUnvalidated(map[string]any{"can": []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(n.Encode(), 0)
	wantStatus(t, err, 401)
}

// Only rules at top level or nested only in all fix /resource (§2.1,
// v0.68): a test under not, any or if never does, so a readScope key
// refuses such a read grant (§C.4).
func TestV073FixesResourceOnlyThroughAll(t *testing.T) {
	is := func(name string) map[string]any {
		return map[string]any{"op": "test", "path": "/resource", "value": name}
	}
	f := newFixture(t, map[string]any{"readScope": "resource"})
	for name, rule := range map[string]any{
		"not": map[string]any{"not": is("x")},
		"any": map[string]any{"any": []any{is("x")}},
		"if":  map[string]any{"if": []any{is("x")}, "then": []any{is("x")}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(roundtrip(t, mustMint(t, f, map[string]any{"rules": []any{rule}})), f.env())
			wantStatus(t, err, 403)
		})
	}
	v, err := Verify(roundtrip(t, mustMint(t, f, map[string]any{"rules": []any{map[string]any{"all": []any{is("x")}}}})), f.env())
	if err != nil || !v.FixesResource() {
		t.Fatalf("all: %v", err)
	}
}

// A grant whose rules don't compile is invalid (§6.4.2, §6.6): Decode
// refuses it (401), so every request that doesn't ignore the grant does,
// not only one that evaluates the rule (v0.63, v0.65).
func TestV073RulesCompiledAtDecode(t *testing.T) {
	f := newFixture(t, nil)
	for name, rule := range map[string]any{
		"unknown op":    map[string]any{"op": "frob", "path": "/action"},
		"no form":       map[string]any{"path": "/action"},
		"nested":        map[string]any{"all": []any{map[string]any{"not": map[string]any{"op": "test"}}}},
		"backreference": map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": `(a)\1`}},
	} {
		g := mustMint(t, f, map[string]any{"rules": []any{rule}})
		_, err := Decode(g.Encode(), 0)
		wantStatus(t, err, 401)
		if !strings.Contains(err.Error(), "rules/0") {
			t.Fatalf("%s: %v", name, err)
		}
		// A narrowing block's rules too.
		n, _ := mustMint(t, f, nil).Narrow(map[string]any{"rules": []any{rule}})
		_, err = Decode(n.Encode(), 0)
		wantStatus(t, err, 401)
	}
	ok := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^a"}}
	if _, err := Decode(mustMint(t, f, map[string]any{"rules": []any{ok}}).Encode(), 0); err != nil {
		t.Fatal(err)
	}
}

// rulesPerGrant counts every rule form of the token's blocks, nested ones
// included (§12.2), and DecodeLimited refuses a token over it, as a
// request-shape error before its rules are compiled (§C.8).
func TestV073RulesPerGrantAtDecode(t *testing.T) {
	leaf := map[string]any{"op": "test", "path": "/action", "value": "read"}
	if n := rules.CountForms(map[string]any{"all": []any{leaf, map[string]any{"not": leaf}}}); n != 4 {
		t.Fatalf("all/not: %d", n)
	}
	if n := rules.CountForms(map[string]any{"if": []any{leaf}, "then": []any{leaf, map[string]any{"any": []any{leaf}}}}); n != 5 {
		t.Fatalf("if/then/any: %d", n)
	}
	f := newFixture(t, nil)
	nested := map[string]any{"all": []any{leaf, leaf, map[string]any{"any": []any{leaf, leaf}}}} // 6 forms
	g := mustMint(t, f, map[string]any{"rules": []any{nested}})
	n, _ := g.Narrow(map[string]any{"rules": []any{leaf}})
	tok := n.Encode()
	if _, err := DecodeLimited(tok, Limits{Rules: 7}); err != nil {
		t.Fatal(err)
	}
	_, err := DecodeLimited(tok, Limits{Rules: 6})
	var tm *TooManyRulesError
	if !errors.As(err, &tm) || !errors.Is(err, ErrTooManyRules) || tm.Count != 7 || tm.Max != 6 {
		t.Fatalf("want too many rules (7 of 6), got %v", err)
	}
	// Counted before the rules are compiled: an oversized grant whose rule
	// doesn't compile is the limit's.
	bad := mustMint(t, f, map[string]any{"rules": []any{leaf, map[string]any{"op": "frob"}}})
	if _, err := DecodeLimited(bad.Encode(), Limits{Rules: 1}); !errors.Is(err, ErrTooManyRules) {
		t.Fatalf("want too many rules, got %v", err)
	}
	// grantSize comes first.
	if _, err := DecodeLimited(tok, Limits{Size: 10, Rules: 1}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want too large, got %v", err)
	}
}

// §6.4.2 makes compare with in and a literal that isn't an array a valid
// rule, false when evaluated: compiling rules at decode doesn't make a
// grant carrying it invalid.
func TestV073CompareInLiteralAtDecode(t *testing.T) {
	f := newFixture(t, nil)
	rule := map[string]any{"op": "compare", "path": "/resource", "in": map[string]any{"value": "a"}}
	g := mustMint(t, f, map[string]any{"rules": []any{rule}})
	if _, err := Decode(g.Encode(), 0); err != nil {
		t.Fatalf("root block: %v", err)
	}
	n, _ := mustMint(t, f, nil).Narrow(map[string]any{"rules": []any{rule}})
	if _, err := Decode(n.Encode(), 0); err != nil {
		t.Fatalf("narrowing block: %v", err)
	}
}
