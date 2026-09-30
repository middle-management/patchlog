package grantcheck_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

type fixture struct {
	t                     *testing.T
	s                     *clienttest.Server
	admin, issuer, scoped clienttest.Key
	adminC                *client.Client
	ch                    *grantcheck.Checker
}

func newFixture(t *testing.T) *fixture {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	f := &fixture{t: t, s: s, admin: clienttest.NewKey("admin"), issuer: clienttest.NewKey("issuer"), scoped: clienttest.NewKey("scoped")}
	scoped := f.scoped.Entry("read")
	scoped["attrs"] = map[string]any{"type": "object", "properties": map[string]any{"level": map[string]any{"maximum": 2}}}
	scoped["readScope"] = "resource"
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec")))
	must(op.CreateNamespace(ctx, "sec", map[string]any{
		"read": "grant",
		"keys": []any{f.admin.Entry("*"), f.issuer.Entry("read", "append", "create"), scoped},
		"roles": map[string]any{
			"reader":   map[string]any{"can": []any{"read"}},
			"prefixed": map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": "^pub-"}}}},
		},
	}))
	f.adminC = s.Client(t, client.WithBearer(f.grant(f.admin, "user:root", []string{"sec", "rel"}, []string{"read", "config", "branch", "create"})))
	svc := s.Client(t, client.WithBearer(f.grant(f.admin, "svc:indexer", []string{"sec", "rel"}, []string{"read"})))
	f.ch = grantcheck.New(svc, grantcheck.WithClock(s.Now), grantcheck.WithTTL(0))
	return f
}

func (f *fixture) grant(k clienttest.Key, sub string, ns, can []string, extra ...map[string]any) string {
	return k.Grant(f.t, f.s.Now(), sub, ns, can, extra...)
}

func authStatus(err error) int {
	var ae *grant.AuthError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// serverReads asks the origin itself whether the bearer can read resource
// name ("" = the namespace head), for cross-checking decisions.
func (f *fixture) serverReads(t *testing.T, ns, name, token string) bool {
	c := f.s.Client(t, client.WithBearer(token))
	var err error
	if name == "" {
		_, err = c.NSHead(context.Background(), ns)
	} else {
		var h *client.Head
		h, err = c.Head(context.Background(), ns, name)
		if err == nil && h.State == client.NotFound {
			return false
		}
	}
	return err == nil
}

func TestCheckRead(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	for _, n := range []string{"a", "pub-x"} {
		must(f.adminC.CreateDoc(ctx, "sec", n, map[string]any{}))
	}
	cases := []struct {
		name     string
		token    string
		resource string
		allowed  bool
		status   int // expected *grant.AuthError status, 0 = none
	}{
		{"reader", f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}), "a", true, 0},
		{"reader whole ns", f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}), "", true, 0},
		{"no read verb", f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"append"}), "a", false, 0},
		{"other ns", f.grant(f.issuer, "user:bob", []string{"other"}, []string{"read"}), "a", false, 403},
		{"verb beyond key", f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read", "purge"}), "a", false, 403},
		{"fixed resource ok", f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}}), "a", true, 0},
		{"fixed resource other", f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}}), "pub-x", false, 0},
		{"role reader", f.grant(f.issuer, "user:bob", []string{"sec"}, nil, map[string]any{"roles": []any{"reader"}}), "a", true, 0},
		{"role prefixed ok", f.grant(f.issuer, "user:bob", []string{"sec"}, nil, map[string]any{"roles": []any{"prefixed"}}), "pub-x", true, 0},
		{"role prefixed no", f.grant(f.issuer, "user:bob", []string{"sec"}, nil, map[string]any{"roles": []any{"prefixed"}}), "a", false, 0},
		{"unknown role", f.grant(f.issuer, "user:bob", []string{"sec"}, nil, map[string]any{"roles": []any{"ghost"}}), "a", false, 0},
		{"attrs ok", f.grant(f.scoped, "user:li", []string{"sec"}, []string{"read"}, map[string]any{"attrs": map[string]any{"level": 1}, "rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}}), "a", true, 0},
		{"attrs too high", f.grant(f.scoped, "user:li", []string{"sec"}, []string{"read"}, map[string]any{"attrs": map[string]any{"level": 3}}), "a", false, 403},
		{"unknown key", f.grant(clienttest.NewKey("ghost"), "user:x", []string{"sec"}, []string{"read"}), "a", false, 401},
		{"garbage", "garbage", "a", false, 401},
		{"missing", "", "a", false, 401},
	}
	for _, tc := range cases {
		d, err := f.ch.CheckRead(ctx, "sec", tc.token, tc.resource)
		if got := authStatus(err); got != tc.status {
			t.Errorf("%s: auth status %d (%v), want %d", tc.name, got, err, tc.status)
			continue
		}
		if err != nil && tc.status == 0 {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if d.Allowed != tc.allowed {
			t.Errorf("%s: allowed %v (%s), want %v", tc.name, d.Allowed, d.Reason, tc.allowed)
		}
		// The origin agrees (reading the resource or the namespace).
		if tc.token != "" && f.serverReads(t, "sec", tc.resource, tc.token) != tc.allowed {
			t.Errorf("%s: the server disagrees (server allows=%v)", tc.name, !tc.allowed)
		}
	}

	// ReadsAll.
	v := must(f.ch.Verify(ctx, "sec", f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"})))
	if !f.ch.ReadsAll(v) {
		t.Error("plain reader should read all")
	}
	v = must(f.ch.Verify(ctx, "sec", f.grant(f.issuer, "user:bob", []string{"sec"}, nil, map[string]any{"roles": []any{"prefixed"}})))
	if f.ch.ReadsAll(v) {
		t.Error("prefixed role reads only some")
	}

	// Revocation: takes effect once the checker sees the new head.
	tok := f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"})
	g := must(grant.Decode(tok, 0))
	cfgID := must(f.adminC.NSHead(ctx, "sec")).Config
	cr := must(f.adminC.PatchConfig(ctx, "sec", cfgID, []any{map[string]any{"op": "add", "path": "/revoked", "value": []any{g.RevocationIDs()[0]}}}))
	f.ch.Observe("sec", cr.NSID)
	if _, err := f.ch.Verify(ctx, "sec", tok); authStatus(err) != 403 {
		t.Fatalf("revoked: %v", err)
	}
	if f.serverReads(t, "sec", "a", tok) {
		t.Fatal("server still reads with the revoked grant")
	}
}

func TestBranchKeysFollowBase(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	must(f.adminC.CreateDoc(ctx, "sec", "a", map[string]any{}))
	own := clienttest.NewKey("own")
	must(f.adminC.CreateBranch(ctx, "sec", client.BranchRequest{Name: "rel",
		Patches: []any{map[string]any{"op": "add", "path": "/keys/-", "value": own.Entry("read")}}}))

	issuerTok := f.grant(f.issuer, "user:bob", []string{"rel"}, []string{"read"})
	ownTok := f.grant(own, "user:eve", []string{"rel"}, []string{"read"})
	for _, tok := range []string{issuerTok, ownTok} {
		d, err := f.ch.CheckRead(ctx, "rel", tok, "a")
		if err != nil || !d.Allowed {
			t.Fatalf("branch read: %v %+v", err, d)
		}
	}
	cfg := must(f.ch.Config(ctx, "rel"))
	if cfg.Base != "sec" || len(cfg.Keys) != 4 {
		t.Fatalf("branch config %+v", cfg)
	}

	// Replace the issuer key in the base (via its pub: a replace of an
	// array element inserts in internal/patch, see the package report): the branch copy stops working,
	// the branch's own key keeps working.
	newIssuer := clienttest.NewKey("issuer")
	cfgID := must(f.adminC.NSHead(ctx, "sec")).Config
	must(f.adminC.PatchConfig(ctx, "sec", cfgID, []any{map[string]any{"op": "replace", "path": "/keys/1/pub", "value": newIssuer.Pub}}))
	f.ch.Invalidate()
	if _, err := f.ch.Verify(ctx, "rel", issuerTok); authStatus(err) != 401 {
		t.Fatalf("stale base key accepted in branch: %v", err)
	}
	if f.serverReads(t, "rel", "a", issuerTok) {
		t.Fatal("server accepts the stale key")
	}
	if _, err := f.ch.Verify(ctx, "rel", ownTok); err != nil {
		t.Fatalf("branch's own key: %v", err)
	}

	// A revocation in the base applies to the branch.
	g := must(grant.Decode(ownTok, 0))
	cfgID = must(f.adminC.NSHead(ctx, "sec")).Config
	must(f.adminC.PatchConfig(ctx, "sec", cfgID, []any{map[string]any{"op": "add", "path": "/revoked", "value": []any{g.RevocationIDs()[0]}}}))
	// TTL 0: the moved head is noticed without Observe.
	if _, err := f.ch.Verify(ctx, "rel", ownTok); authStatus(err) != 403 {
		t.Fatalf("base revocation ignored: %v", err)
	}
	if f.serverReads(t, "rel", "a", ownTok) {
		t.Fatal("server ignores the base revocation")
	}
}

func TestRequireAt(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	at := clienttest.NewKey("at")
	e := at.Entry("read")
	e["requireAt"] = true
	cfgID := must(f.adminC.NSHead(ctx, "sec")).Config
	must(f.adminC.PatchConfig(ctx, "sec", cfgID, []any{map[string]any{"op": "add", "path": "/keys/-", "value": e}}))
	head := must(f.adminC.NSHead(ctx, "sec")).ID

	ok := f.grant(at, "user:a", []string{"sec"}, []string{"read"}, map[string]any{"at": head})
	if _, err := f.ch.Verify(ctx, "sec", ok); err != nil {
		t.Fatalf("at at head: %v", err)
	}
	missing := f.grant(at, "user:a", []string{"sec"}, []string{"read"})
	bogus := f.grant(at, "user:a", []string{"sec"}, []string{"read"}, map[string]any{"at": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	for _, tok := range []string{missing, bogus} {
		if _, err := f.ch.Verify(ctx, "sec", tok); authStatus(err) != 403 {
			t.Fatalf("bad at accepted: %v", err)
		}
	}
	// An older at is fine without maxLag.
	must(f.adminC.CreateDoc(ctx, "sec", "z", map[string]any{}))
	if _, err := f.ch.Verify(ctx, "sec", ok); err != nil {
		t.Fatalf("older at: %v", err)
	}
}

func TestPublicAndSubjectSets(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	op := f.s.Client(t, client.WithBearer(f.s.OperatorGrant(t, "pub")))
	must(op.CreateNamespace(ctx, "pub", map[string]any{"read": "public", "keys": []any{f.issuer.Entry("read")}}))
	d, err := f.ch.CheckRead(ctx, "pub", "", "x")
	if err != nil || !d.Allowed || !d.Public || d.Verified != nil {
		t.Fatalf("public anonymous: %v %+v", err, d)
	}

	tok := f.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"groups": []any{"desk", "group:ops", "desk"}})
	v := must(f.ch.Verify(ctx, "sec", tok))
	subs := grantcheck.SubjectSet(v, true)
	want := []string{"group:desk", "group:ops", "user:bob"}
	if len(subs) != 3 || subs[0] != want[0] || subs[1] != want[1] || subs[2] != want[2] {
		t.Fatalf("subjects %v", subs)
	}
	if g := grantcheck.SubjectSet(v, false); len(g) != 2 {
		t.Fatalf("group subjects %v", g)
	}
	sum := sha256.Sum256([]byte(`["group:desk","group:ops","user:bob"]`))
	gs := ids.FromBytes(sum[:20]).String()
	if got := grantcheck.SubjectSetID([]string{"user:bob", "group:ops", "group:desk"}); got != gs {
		t.Fatalf("gs %s want %s", got, gs)
	}
	if string(jsonv.Canonical([]any{"b", "a"})) != `["b","a"]` {
		t.Fatal("canonical arrays keep order")
	}
}
