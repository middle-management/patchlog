package core

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// Cross-review (conformance lens): scenario tests for the v0.77 scenarios
// that had none at the origin.

func v077xCookie(t *testing.T, w *v75World, cred Credentials) (Credentials, string) {
	t.Helper()
	res, err := w.e.IssueEdgeGrants(context.Background(), []string{cred.Bearer})
	if err != nil || len(res.Grants) != 1 || res.Grants[0].GS == "" {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	g := res.Grants[0]
	return Credentials{Edge: &EdgeGrant{NS: g.NS, GS: g.GS, Prefix: "/ns/" + g.NS + "/g/" + g.GS, Exp: w.now().Add(10 * time.Minute)}}, g.GS
}

// Access 111: li through access-02, bo through reader-01,
// same deciding subjects and rules -> different gs. access-02's pub then
// changes and a third reader exchanges under the new key -> li's old
// cookie at a later at -> 403; her exchange under the old grant -> 401.
func TestV077XconfScenario111(t *testing.T) {
	t.Parallel()
	a2Pub, a2Priv := grant.GenerateKey()
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) {
		doc["keys"] = append(doc["keys"].([]any), map[string]any{"kid": "access-02", "alg": "ed25519", "pub": a2Pub,
			"can": []any{"read"}, "maxTtl": "PT15M",
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}})
	}})
	w.seed()
	grantBy := func(priv []byte, kid, sub string) Credentials {
		return w.cred(priv, map[string]any{"kid": kid, "sub": sub, "groups": []any{"editors", "interns"}, "roles": []any{"reader"},
			"ns": []any{"matches"}, "can": []any{"read"},
			"exp": w.now().Add(10 * time.Minute).UTC().Format(time.RFC3339)})
	}
	li := grantBy(a2Priv, "access-02", "user:li")
	bo := grantBy(w.catPriv, "reader-01", "user:li")
	liCookie, liGS := v077xCookie(t, w, li)
	_, boGS := v077xCookie(t, w, bo)
	if liGS == boGS {
		t.Fatalf("same gs %s through two keys", liGS)
	}
	newPub, newPriv := grant.GenerateKey()
	w.patchConfig("matches", map[string]any{"op": "replace", "path": "/keys/2/pub", "value": newPub})
	third := grantBy(newPriv, "access-02", "user:zed")
	v077xCookie(t, w, third)
	w.put("matches", "later", map[string]any{"title": "x"})
	if red, st := v76fRedirect(t, w, "matches", liGS, liCookie); st != 403 {
		t.Errorf("li's old cookie after access-02's pub changed: %+v %d, want 403", red, st)
	}
	if _, err := w.e.IssueEdgeGrants(context.Background(), []string{li.Bearer}); v75Status(err) != 401 {
		t.Errorf("li's exchange under the old grant: %v, want 401", err)
	}
}

// Tree-derived access 112 (key half): matches keeps reader-01 but drops
// read from its can -> li on her cookie at a later at -> 403.
func TestV077XconfScenario112Key(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	cookie, gs := v077xCookie(t, w, w.li())
	if red, st := v76fRedirect(t, w, "matches", gs, cookie); red == nil {
		t.Fatalf("before: %d", st)
	}
	w.patchConfig("matches", map[string]any{"op": "replace", "path": "/keys/1/can", "value": []any{"create"}})
	if red, st := v76fRedirect(t, w, "matches", gs, cookie); st != 403 {
		t.Errorf("after reader-01 lost read: %+v %d, want 403", red, st)
	}
}

// Tree-derived access 113 (origin half): after matches-r7 is created,
// matches edits only reader-01's maxTtl -> a partial reader of the branch
// -> filtered /heads 403; the exchange gives no /ns/matches-r7/g/{gs}.
// Since v0.78 no branch is covered (§7.9 Where), before the edit too.
func TestV077XconfScenario113(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	if _, err := w.e.CreateBranch(ctx, Request{NS: "matches", Cred: w.admin}, BranchRequest{Name: "matches-r7", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	r7 := w.li(map[string]any{"ns": []any{"matches-r7"}})
	if _, st := v76fRedirect(t, w, "matches-r7", "", r7); st != 403 {
		t.Fatalf("branch before: %d, want 403", st)
	}
	gs := v075GS(t, w, w.li())
	w.patchConfig("matches", map[string]any{"op": "replace", "path": "/keys/1/maxTtl", "value": "PT14M"})
	if st := v75Status(w.e.FilteredCurrent(ctx, "matches-r7", gs, "/heads", r7)); st != 403 {
		t.Errorf("branch after maxTtl edit: %d, want 403", st)
	}
	res, err := w.e.IssueEdgeGrants(ctx, []string{r7.Bearer})
	if err == nil {
		for _, g := range res.Grants {
			for _, p := range g.Prefixes() {
				if len(p) > len("/ns/matches-r7/g/") && p[:len("/ns/matches-r7/g/")] == "/ns/matches-r7/g/" {
					t.Errorf("exchange still gives %s", p)
				}
			}
		}
	}
}

// Grant scope 63 and 64: a private namespace. A grant
// fixed to derby -> namespace log or events -> 403, never 404; a grant
// whose block rule is not /resource = "secret" -> /r/priv/secret 404,
// events 403.
func TestV077XconfGrantScope63And64(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.mkNS("priv", map[string]any{"read": "grant", "keys": []any{w.kEntry()}})
	ctx := context.Background()
	adm := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"priv"}, "can": []any{"read", "create", "append"}})
	for _, n := range []string{"derby", "secret", "other"} {
		if _, err := w.e.WriteResource(ctx, Request{NS: "priv", Cred: adm}, Item{Resource: n, IfNoneMatch: true,
			Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"t": n}}}}}}); err != nil {
			t.Fatal(err)
		}
	}
	info, err := w.e.NamespaceHead(ctx, "priv", adm)
	if err != nil {
		t.Fatal(err)
	}
	fixed := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:li", "ns": []any{"priv"}, "can": []any{"read"},
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "derby"}}})
	if _, err := w.e.NamespaceLog(ctx, "priv", info.Head, "", 0, fixed); v75Status(err) != 403 {
		t.Errorf("63: fixed grant, namespace log: %v, want 403", err)
	}
	if _, err := w.e.NamespaceEvents(ctx, "priv", "", 0, fixed); v75Status(err) != 403 {
		t.Errorf("63: fixed grant, events: %v, want 403", err)
	}
	if _, err := w.e.ResourceHead(ctx, "priv", "other", fixed); v75Status(err) != 404 {
		t.Errorf("63: fixed grant, /r/priv/other: %v, want 404", err)
	}
	notSecret := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:li", "ns": []any{"priv"}, "can": []any{"read"},
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"not": map[string]any{"const": "secret"}}}}})
	if _, err := w.e.ResourceHead(ctx, "priv", "secret", notSecret); v75Status(err) != 404 {
		t.Errorf("64: /r/priv/secret: %v, want 404", err)
	}
	// A partial reader (§7.9): redirected to its filtered events.
	if _, err := w.e.NamespaceEvents(ctx, "priv", "", 0, notSecret); func() bool { _, ok := err.(*FilteredRedirect); return !ok }() {
		t.Errorf("64: events: %v, want a redirect", err)
	}
}

// Tree-derived access 118: li's effective role reader also has includes
// and x-note -> /principal's roles entry holds only name, can and rules.
func TestV077XconfScenario118(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) {
		doc["roles"] = map[string]any{"reader": map[string]any{"can": []any{"read"}, "includes": []any{"viewer"}, "x-note": "n"},
			"viewer": map[string]any{"can": []any{"read"}}}
	}})
	w.seed()
	ans, err := w.e.Principal(context.Background(), "matches", w.li())
	if err != nil {
		t.Fatal(err)
	}
	roles, _ := ans.Body["roles"].([]any)
	if len(roles) != 1 {
		t.Fatalf("roles %v", roles)
	}
	r := roles[0].(map[string]any)
	if len(r) != 3 || r["name"] != "reader" || r["can"] == nil || r["rules"] == nil {
		t.Errorf("role entry %v, want exactly name, can, rules", r)
	}
}

// Cross-review (conformance lens), §7.9 gs: a gs's subjects carry "the
// string scope:{digest} of §A.4's marker for {ns}", whose digest covers
// the rules and the key's key: string (grantcheck.ScopeKeyDigest), not the
// rules' digest alone.
func TestV077XrevGSScopeSubjectIsMarkerDigest(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	li := w.li()
	w.inTx(func(t2 *tx) {
		n := t2.nsByName("matches")
		a, _, _, err := t2.nsAccess(n, li)
		if err != nil {
			t.Fatal(err)
		}
		d, ok := grantcheck.ReadsScope(a.verified)
		if !ok {
			t.Fatal("li's reads refer to /now")
		}
		fv := v075View(t, t2, "matches", li)
		want := grantcheck.ScopePrefix + grantcheck.ScopeKeyDigest(d, a.verified.Key.Kid, keyPub(*a.verified.Key))
		if !slices.Contains(fv.subjects, want) {
			t.Errorf("subjects %v, want %s, §A.4's marker digest", fv.subjects, want)
		}
		if slices.Contains(fv.subjects, grantcheck.ScopePrefix+d) {
			t.Errorf("subjects %v carry the rules' digest alone", fv.subjects)
		}
	})
}
