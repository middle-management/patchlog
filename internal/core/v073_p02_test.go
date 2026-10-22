package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// v073Create writes a create of name in n under cred.
func v073Create(e *Engine, cred Credentials, name string) (*WriteResult, error) {
	it := Item{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}}
	return e.WriteResource(context.Background(), Request{NS: "n", Cred: cred}, it)
}

// v073Status is the status of a core refusal, 0 for none.
func v073Status(err error) int {
	if e, ok := err.(*Error); ok {
		return e.Status
	}
	if err != nil {
		return -1
	}
	return 0
}

// The server stores a grant's authority block alone, as a SignedBlock
// (§C.3, §C.8, v0.63), and serves it as stored; a row stored before, the
// whole chain without proof, is served as its authority block too.
func TestV073StoredGrantIsAuthorityBlock(t *testing.T) {
	var clock atomic.Int64
	e, mint, _ := authEngine(t, &clock)
	ctx := context.Background()
	root, err := grant.Decode(mint(map[string]any{"kid": "k", "sub": "user:w", "ns": []any{"n"}, "can": []any{"create", "read"}}), 0)
	if err != nil {
		t.Fatal(err)
	}
	narrowed, err := root.Narrow(map[string]any{"via": "svc:importer"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v073Create(e, Credentials{Bearer: narrowed.Encode()}, "a"); err != nil {
		t.Fatal(err)
	}
	gid := narrowed.ID()
	authority := narrowed.SignedBlocks()[0]
	var stored []byte
	if err := e.read(ctx, func(t *tx) error {
		return t.QueryRow(`SELECT blocks FROM grants WHERE id = ?`, gid[:]).Scan(&stored)
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, authority) || bytes.Contains(stored, []byte("svc:importer")) {
		t.Fatalf("stored %d bytes, want the %d-byte authority SignedBlock", len(stored), len(authority))
	}
	reader := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"n"}, "can": []any{"read"}})}
	want := base64.RawURLEncoding.EncodeToString(authority)
	served := func() {
		t.Helper()
		doc, err := e.Grant(ctx, "n", gid.String(), reader)
		if err != nil {
			t.Fatal(err)
		}
		if doc.Stored != want || doc.ID != gid.String() {
			t.Fatalf("served %v", doc.Stored)
		}
	}
	served()

	// A row from before: the chain as a Biscuit without proof.
	var legacy []byte
	for i, sb := range narrowed.SignedBlocks() {
		field := byte(3)
		if i == 0 {
			field = 2
		}
		legacy = append(legacy, field<<3|2)
		legacy = binary.AppendUvarint(legacy, uint64(len(sb)))
		legacy = append(legacy, sb...)
	}
	if err := e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`UPDATE grants SET blocks = ? WHERE id = ?`, t.e.blobArg(legacy), gid[:])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	served()
	if g, err := grant.ParseStored(legacy); err != nil || g.ID() != gid {
		t.Fatal("legacy row")
	}
}

// v073Env is an engine with authentication on (v073Engine): mint mints
// grants of the key k every namespace it creates lists, opMint operator
// grants, and create creates a namespace under the operator grant.
type v073Env struct {
	*Engine
	mint, opMint func(root map[string]any) string
	create       func(ns string, doc map[string]any)
}

// v073Engine opens an engine with authentication on, as authEngine does,
// with lim the namespace defaults and max the deployment maximums (fast
// write rates in both), and creates namespace n with document doc plus a
// key k (can "*").
func v073Engine(t *testing.T, lim, max Limits, doc map[string]any) *v073Env {
	t.Helper()
	opPub, opPriv := grant.GenerateKey()
	ops, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": opPub, "can": []any{"*"}}}))
	if err != nil {
		t.Fatal(err)
	}
	fast := Rate{1e9, 1e9}
	for _, l := range []*Limits{&lim, &max} {
		l.RatePerResource, l.RatePerPrincipal, l.RatePerNamespace = fast, fast, fast
	}
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), OperatorKeys: ops, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, Maximums: max, TailInterval: authTailEvery, Purger: discardPurger{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	mint := func(priv ed25519.PrivateKey, root map[string]any) string {
		t.Helper()
		if _, ok := root["exp"]; !ok {
			root["exp"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		}
		g, err := grant.Mint(root, priv)
		if err != nil {
			t.Fatal(err)
		}
		return g.Encode()
	}
	pub, priv := grant.GenerateKey()
	key := map[string]any{"kid": "k", "alg": "ed25519", "pub": pub, "can": []any{"*"}}
	env := &v073Env{Engine: e,
		mint:   func(root map[string]any) string { return mint(priv, root) },
		opMint: func(root map[string]any) string { return mint(opPriv, root) }}
	env.create = func(ns string, doc map[string]any) {
		t.Helper()
		d := map[string]any{"keys": []any{key}}
		for k, v := range doc {
			d[k] = v
		}
		opG := env.opMint(map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{ns}, "can": []any{"config"}})
		if _, err := e.WriteConfig(context.Background(), Request{NS: ns, Cred: Credentials{Bearer: opG}}, ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": d}}}); err != nil {
			t.Fatal(err)
		}
	}
	env.create("n", doc)
	return env
}

// v073Limit checks err is a 413 limit refusal naming key, with measured and
// max when max is positive.
func v073Limit(t *testing.T, what string, err error, key string, measured, max int64) {
	t.Helper()
	e, ok := err.(*Error)
	if !ok || e.Status != 413 || e.Body["code"] != "limit" || e.Body["limit"] != key {
		t.Fatalf("%s: want 413 limit %s, got %v", what, key, err)
	}
	if max > 0 && (e.Body["measured"] != measured || e.Body["max"] != max) {
		t.Fatalf("%s: measured %v max %v, want %d of %d", what, e.Body["measured"], e.Body["max"], measured, max)
	}
}

// v073Leaf is a rule form that passes for every request.
var v073Leaf = map[string]any{"op": "test", "path": "/action", "exists": true}

// v073Rules returns rules of n forms in all: one all of n-1 leaves.
func v073Rules(n int) []any {
	leaves := make([]any, n-1)
	for i := range leaves {
		leaves[i] = v073Leaf
	}
	return []any{map[string]any{"all": leaves}}
}

// A grant whose rule doesn't compile is invalid: 401 on every request that
// doesn't ignore it, /principal and edge-grant issuance included, and
// before the ns check (§6.6, §C.2, v0.63, F-C1 default).
func TestV073GrantRuleCompiledAtDecode(t *testing.T) {
	e := v073Engine(t, DefaultLimits(), DefaultMaximums(), map[string]any{"read": "grant"})
	mint := e.mint
	ctx := context.Background()
	writer := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:w", "ns": []any{"n"}, "can": []any{"create"}})}
	if _, err := v073Create(e.Engine, writer, "a"); err != nil {
		t.Fatal(err)
	}
	for name, rule := range map[string]any{
		"unknown op": map[string]any{"op": "frob", "path": "/action"},
		"lookahead":  map[string]any{"op": "test", "path": "/principal/id", "schema": map[string]any{"pattern": "(?=user)"}},
	} {
		bad := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:w", "ns": []any{"n"}, "can": []any{"create", "read"}, "rules": []any{rule}})}
		if _, err := v073Create(e.Engine, bad, "b"); v073Status(err) != 401 {
			t.Fatalf("%s: write %v", name, err)
		}
		if _, err := e.ResourceHead(ctx, "n", "a", bad); v073Status(err) != 401 {
			t.Fatalf("%s: read %v", name, err)
		}
		if _, err := e.Principal(ctx, "n", bad); v073Status(err) != 401 {
			t.Fatalf("%s: principal %v", name, err)
		}
		if _, err := e.IssueEdgeGrants(ctx, []string{bad.Bearer}); v073Status(err) != 401 {
			t.Fatalf("%s: edge grants %v", name, err)
		}
		other := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:w", "ns": []any{"elsewhere"}, "can": []any{"create"}, "rules": []any{rule}})}
		if _, err := v073Create(e.Engine, other, "b"); v073Status(err) != 401 {
			t.Fatalf("%s: not naming n: %v", name, err)
		}
	}
}

// rulesPerGrant counts every rule form of a grant's blocks, nested ones
// included, at the deployment's value, and is 413 before step 1 and before
// the ns check on every request that doesn't ignore the grant (§C.8,
// §12.2, v0.63, v0.73). Public reads ignore the grant.
func TestV073RulesPerGrantBeforeNSCheck(t *testing.T) {
	e := v073Engine(t, DefaultLimits(), DefaultMaximums(), map[string]any{"read": "grant"})
	mint := e.mint
	e.create("pub", map[string]any{"read": "public"})
	ctx := context.Background()
	writer := func(ns string) Credentials {
		return Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:w", "ns": []any{ns}, "can": []any{"create"}})}
	}
	for _, ns := range []string{"n", "pub"} {
		if _, err := e.WriteResource(ctx, Request{NS: ns, Cred: writer(ns)}, Item{Resource: "a", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}}); err != nil {
			t.Fatal(err)
		}
	}
	// 32 forms pass; two top-level rules nesting 34 forms between them
	// don't, though the old count, of top-level rules, saw 2.
	at := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:w", "ns": []any{"n"}, "can": []any{"create", "read"}, "rules": v073Rules(32)})}
	if _, err := v073Create(e.Engine, at, "b"); err != nil {
		t.Fatal(err)
	}
	over := map[string]any{"kid": "k", "sub": "user:w", "ns": []any{"n", "pub"}, "can": []any{"create", "read"}, "rules": append(v073Rules(18), v073Rules(18)...)}
	tok := Credentials{Bearer: mint(over)}
	_, err := v073Create(e.Engine, tok, "c")
	v073Limit(t, "write", err, "rulesPerGrant", 36, 32)
	_, err = e.ResourceHead(ctx, "n", "a", tok)
	v073Limit(t, "private read", err, "rulesPerGrant", 36, 32)
	_, err = e.Principal(ctx, "n", tok)
	v073Limit(t, "principal", err, "rulesPerGrant", 36, 32)
	_, err = e.IssueEdgeGrants(ctx, []string{tok.Bearer})
	v073Limit(t, "edge grants", err, "rulesPerGrant", 36, 32)
	_, err = e.ResourceHead(ctx, "nope", "a", tok)
	v073Limit(t, "absent namespace", err, "rulesPerGrant", 36, 32)
	over["ns"] = []any{"elsewhere"}
	_, err = v073Create(e.Engine, Credentials{Bearer: mint(over)}, "c")
	v073Limit(t, "not naming n", err, "rulesPerGrant", 36, 32)
	if _, err := e.ResourceHead(ctx, "pub", "a", tok); err != nil {
		t.Fatalf("a public read ignores the grant: %v", err)
	}
}

// grantSize and rulesPerGrant are deployment only (§12.2, v0.63): a
// namespace's values, here the defaults the deployment gives namespaces,
// no longer lower them.
func TestV073GrantLimitsDeploymentOnly(t *testing.T) {
	lim := DefaultLimits()
	lim.RulesPerGrant, lim.GrantSize = 2, 300
	e := v073Engine(t, lim, DefaultMaximums(), map[string]any{"read": "grant"})
	g := e.mint(map[string]any{"kid": "k", "sub": "user:w", "ns": []any{"n"}, "can": []any{"create"}, "rules": v073Rules(3),
		"attrs": map[string]any{"pad": strings.Repeat("x", 300)}})
	if _, err := v073Create(e.Engine, Credentials{Bearer: g}, "a"); err != nil {
		t.Fatalf("held to the namespace's grant limits: %v", err)
	}
}

// A grant over grantSize is 413 before the ns check, whatever namespace
// it names (§C.8).
func TestV073OversizeGrantNotNamingNS(t *testing.T) {
	var clock atomic.Int64
	e, mint, _ := authEngine(t, &clock)
	big := mint(map[string]any{"kid": "k", "sub": "user:w", "ns": []any{"elsewhere"}, "can": []any{"create"},
		"attrs": map[string]any{"pad": strings.Repeat("x", 9<<10)}})
	_, err := v073Create(e, Credentials{Bearer: big}, "a")
	v073Limit(t, "write", err, "grantSize", 0, 0)
	_, err = e.ResourceHead(context.Background(), "n", "a", Credentials{Bearer: big})
	v073Limit(t, "read", err, "grantSize", 0, 0)
}

// v073Prefixes lists the prefixes of an exchange's edge grants.
func v073Prefixes(eg *EdgeGrants) []string {
	var out []string
	for _, g := range eg.Grants {
		out = append(out, g.Prefixes()...)
	}
	return out
}

// A qualifying role may refer to /resource when the grant fixes it, and
// then must pass for every name fixed (once if none is); it may not refer
// to /now (§2.1, §C.5.2, v0.65, v0.71).
func TestV073QualifyingRolePerFixedName(t *testing.T) {
	inAB := map[string]any{"op": "compare", "path": "/resource", "in": map[string]any{"value": []any{"a", "b"}}}
	e := v073Engine(t, DefaultLimits(), DefaultMaximums(), map[string]any{"read": "grant", "roles": map[string]any{
		"doc":    map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "doc"}}},
		"ab":     map[string]any{"can": []any{"read"}, "rules": []any{inAB, map[string]any{"op": "test", "path": "/principal/id", "value": "user:r"}}},
		"a-only": map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "compare", "path": "/resource", "eq": map[string]any{"value": "a"}}}},
		"clock":  map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/now", "exists": true}}},
		"plain":  map[string]any{"can": []any{"read"}},
	}})
	ctx := context.Background()
	fix := func(names ...any) []any {
		return []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": names}}}
	}
	for _, c := range []struct {
		name  string
		roles []any
		rules []any
		want  string // "" for 403
	}{
		{"role testing the fixed name", []any{"doc"}, fix("doc"), "/r/n/doc"},
		{"role passing for every name fixed", []any{"ab"}, fix("a", "b"), "/r/n/a /r/n/b"},
		{"role failing for one name fixed", []any{"a-only"}, fix("a", "b"), ""},
		{"one role of two qualifies", []any{"a-only", "ab"}, fix("a", "b"), "/r/n/a /r/n/b"},
		{"role on /resource, nothing fixed", []any{"doc"}, nil, ""},
		{"role on /now", []any{"clock"}, nil, ""},
		{"role on /now, a name fixed", []any{"clock"}, fix("doc"), ""},
		{"role without rules", []any{"plain"}, nil, "/r/n /ns/n"},
	} {
		root := map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"n"}, "roles": c.roles}
		if c.rules != nil {
			root["rules"] = c.rules
		}
		eg, err := e.IssueEdgeGrants(ctx, []string{e.mint(root)})
		if c.want == "" {
			if v073Status(err) != 403 {
				t.Errorf("%s: want 403, got %v", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := strings.Join(v073Prefixes(eg), " "); got != c.want {
			t.Errorf("%s: prefixes %q, want %q", c.name, got, c.want)
		}
	}
}

// A grant naming "*" gets no edge grant, 401: from a namespace key it is
// invalid, and an operator grant authorises no read (§C.4, v0.63). No
// grant at all is 401 too (§C.5.2).
func TestV073EdgeGrantsStarAndNone(t *testing.T) {
	e := v073Engine(t, DefaultLimits(), DefaultMaximums(), map[string]any{"read": "grant"})
	ctx := context.Background()
	for name, tok := range map[string]string{
		"operator":  e.opMint(map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"*"}, "can": []any{"read", "config"}}),
		"namespace": e.mint(map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"*"}, "can": []any{"read"}}),
		"beside n":  e.mint(map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"n", "*"}, "can": []any{"read"}}),
	} {
		if _, err := e.IssueEdgeGrants(ctx, []string{tok}); v073Status(err) != 401 {
			t.Errorf("%s grant naming *: %v", name, err)
		}
	}
	if _, err := e.IssueEdgeGrants(ctx, nil); v073Status(err) != 401 {
		t.Fatalf("no grant: %v", err)
	}
}

// A grant narrowed to roles over a root without roles carries roles, and
// has no effective role: it allows no verb, and /principal says so (§2.1,
// §C.2, v0.66).
func TestV073NarrowedToRolesAllowsNothing(t *testing.T) {
	e := v073Engine(t, DefaultLimits(), DefaultMaximums(), map[string]any{"read": "grant", "roles": map[string]any{
		"reader": map[string]any{"can": []any{"read"}}}})
	ctx := context.Background()
	root, err := grant.Decode(e.mint(map[string]any{"kid": "k", "sub": "user:d", "ns": []any{"n"}, "can": []any{"create", "read"}}), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v073Create(e.Engine, Credentials{Bearer: root.Encode()}, "a"); err != nil {
		t.Fatal(err)
	}
	n, err := root.Narrow(map[string]any{"via": "svc:x", "roles": []any{"reader"}})
	if err != nil {
		t.Fatal(err)
	}
	cred := Credentials{Bearer: n.Encode()}
	if _, err := v073Create(e.Engine, cred, "b"); v073Status(err) != 403 {
		t.Fatalf("create: %v", err)
	}
	if _, err := e.ResourceHead(ctx, "n", "a", cred); v073Status(err) != 404 {
		t.Fatalf("read: %v", err)
	}
	p, err := e.Principal(ctx, "n", cred)
	if err != nil {
		t.Fatal(err)
	}
	if can, roles := p.Body["can"].([]any), p.Body["roles"].([]any); len(can) != 0 || len(roles) != 0 {
		t.Fatalf("principal can %v roles %v", can, roles)
	}
}
