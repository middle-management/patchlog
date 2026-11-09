package core

import (
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
)

// Cross-review (conformance lens): scenario tests for the v0.76
// filtered-read scenarios that had none.

func v076XrevLog(t *testing.T, w *v75World, ns, gs, at string, cred Credentials) ([]map[string]any, int) {
	t.Helper()
	lg, _, err := w.e.FilteredLog(context.Background(), ns, gs, at, "", 0, cred)
	if _, ok := err.(*FilteredRedirect); ok {
		return nil, -1
	}
	if err != nil {
		return nil, v75Status(err)
	}
	return lg.Entries, 0
}

func v076XrevHasEntry(es []map[string]any, kind, res string) bool {
	for _, e := range es {
		if e["kind"] == kind && e["resource"] == res {
			return true
		}
	}
	return false
}

// Scenario 93: derby, visible to li, is deleted, its placement then moved
// into TR (embargo here) -> derby's tombstone isn't shown at a later at.
func TestV076Scenario93(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	li := w.li()
	w.del("matches", "derby")
	red, _ := v76fRedirect(t, w, "matches", "", li)
	if red == nil {
		t.Fatal("no redirect")
	}
	es, st := v076XrevLog(t, w, "matches", red.GS, red.At, li)
	if st != 0 || !v076XrevHasEntry(es, "tombstone", "derby") {
		t.Fatalf("before the move: %d, want derby's tombstone", st)
	}
	w.put("cat-season", "matches.derby", map[string]any{"parents": v75Parents("embargo")})
	red2, _ := v76fRedirect(t, w, "matches", red.GS, li)
	if red2 == nil || red2.At == red.At {
		t.Fatalf("no new at: %+v", red2)
	}
	es, st = v076XrevLog(t, w, "matches", red2.GS, red2.At, li)
	if st != 0 || v076XrevHasEntry(es, "tombstone", "derby") || v076XrevHasEntry(es, "head", "derby") {
		t.Fatalf("after the move: %d %v", st, es)
	}
}

// Scenario 94: a placement in cat-season is purged -> its purge entry
// isn't shown to a partial reader of cat-season.
func TestV076Scenario94(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	cr := w.catReader("user:li", "editors")
	red, st := v76fRedirect(t, w, "cat-season", "", cr)
	if red == nil {
		t.Fatalf("cat-season: %d", st)
	}
	h, err := w.e.ResourceHead(ctx, "cat-season", "matches.shared", w.admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.e.Purge(ctx, Request{NS: "cat-season", Cred: w.admin}, "matches.shared", h.Head, false); err != nil {
		t.Fatal(err)
	}
	red2, st := v76fRedirect(t, w, "cat-season", red.GS, cr)
	if red2 == nil {
		t.Fatalf("after purge: %d", st)
	}
	es, st := v076XrevLog(t, w, "cat-season", red2.GS, red2.At, cr)
	if st != 0 {
		t.Fatal(st)
	}
	for _, e := range es {
		if e["resource"] == "matches.shared" {
			t.Errorf("shown: %v %v", e["kind"], e["resource"])
		}
	}
}

// Scenario 95: a cookie for a gs the origin keeps no row for -> 401.
func TestV076Scenario95(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	gs := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches", GS: gs, Prefix: "/ns/matches/g/" + gs, Exp: w.now().Add(10 * time.Minute)}}
	err := w.e.FilteredCurrent(context.Background(), "matches", gs, "/heads", cookie)
	if v75Status(err) != 401 {
		t.Fatalf("%v, want 401", err)
	}
	if e, _ := err.(*Error); e == nil || e.Body["code"] != "unauthenticated" {
		t.Fatalf("%v, want unauthenticated", err)
	}
	// Contrast: a gs the origin does keep a row for (li's, exchanged for
	// matches) is admitted, even with another namespace present.
	li := w.li()
	res, err := w.e.IssueEdgeGrants(context.Background(), []string{li.Bearer})
	if err != nil || len(res.Grants) != 1 {
		t.Fatal(res, err)
	}
	gs2 := res.Grants[0].GS
	w.mkNS("other", map[string]any{"read": "grant", "keys": []any{w.kEntry()}})
	cookie2 := Credentials{Edge: &EdgeGrant{NS: "matches", GS: gs2, Prefix: "/ns/matches/g/" + gs2, Exp: w.now().Add(10 * time.Minute)}}
	if err := w.e.FilteredCurrent(context.Background(), "matches", gs2, "/heads", cookie2); err == nil {
		t.Fatal("nil")
	} else if _, ok := err.(*FilteredRedirect); !ok {
		t.Fatalf("own gs: %v", err)
	}
}

// Scenario 96: matches removes the role li's gs stored as effective ->
// her cookie is 403 at a later at until she exchanges again.
func TestV076Scenario96(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	li := w.li()
	res, err := w.e.IssueEdgeGrants(ctx, []string{li.Bearer})
	if err != nil || len(res.Grants) != 1 {
		t.Fatal(res, err)
	}
	gs := res.Grants[0].GS
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches", GS: gs, Prefix: "/ns/matches/g/" + gs, Exp: w.now().Add(10 * time.Minute)}}
	if red, st := v76fRedirect(t, w, "matches", gs, cookie); red == nil {
		t.Fatalf("before: %d", st)
	}
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/roles/viewer", "value": map[string]any{"can": []any{"read"}}},
		map[string]any{"op": "remove", "path": "/roles/reader"})
	if red, st := v76fRedirect(t, w, "matches", gs, cookie); st != 403 {
		t.Fatalf("after the role went: %+v %d, want 403", red, st)
	}
}

// Scenario 103: matches has no key whose requireAt names cat-season ->
// li at /ns/matches/g/{gs}/heads -> 403; without credentials 401.
func TestV076Scenario103(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) {
		delete(doc["keys"].([]any)[1].(map[string]any), "requireAt")
	}})
	w.seed()
	ctx := context.Background()
	li := w.cred(w.catPriv, map[string]any{"kid": "catalog-01", "sub": "user:li", "groups": []any{"editors"}, "roles": []any{"reader"},
		"ns": []any{"matches"}, "can": []any{"read"}})
	gs := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if st := v75Status(w.e.FilteredCurrent(ctx, "matches", gs, "/heads", li)); st != 403 {
		t.Errorf("li: %d, want 403", st)
	}
	if st := v75Status(w.e.FilteredCurrent(ctx, "matches", gs, "/heads", Credentials{})); st != 401 {
		t.Errorf("no credentials: %d, want 401", st)
	}
}

// Scenario 104: catalog-01 and catalog-02, both requireAt cat-season,
// catalog-02's scope admitting only ^pub- -> a document is listed when
// either key, judged alone, makes it visible. catalog-01's scope admits
// only ^d here, so pub-a is visible through catalog-02 alone and derby
// through catalog-01 alone; the reader is fan, through a key no item
// counts.
func TestV076Scenario104(t *testing.T) {
	t.Parallel()
	pub2, _ := grant.GenerateKey()
	fanPub, fanPriv := grant.GenerateKey()
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) {
		k1 := doc["keys"].([]any)[1].(map[string]any)
		k1["rules"] = []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": "^d"}}}
		doc["keys"] = append(doc["keys"].([]any), map[string]any{"kid": "catalog-02", "alg": "ed25519", "pub": pub2,
			"can": []any{"read"}, "requireAt": "cat-season",
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": "^pub-"}}}},
			v76fFanEntry(fanPub))
	}})
	w.seed()
	w.put("cat-season", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:editors": []any{"reader"},
		"user:li": []any{"reader"}, "group:fan-club": []any{"reader"}}})
	w.put("matches", "pub-a", map[string]any{"title": "a"})
	w.put("cat-season", "matches.pub-a", map[string]any{"parents": v75Parents("season")})
	fw := &v76fWorld{v75World: w, fanPub: fanPub, fanPriv: fanPriv}
	fan := fw.fan("matches", fanPriv)
	red, st := v76fRedirect(t, w, "matches", "", fan)
	if red == nil {
		t.Fatalf("fan: %d", st)
	}
	names, st := v76fHeads(t, w, "matches", red.GS, red.At, fan)
	if st != 0 || !v76fHas(names, "pub-a") || !v76fHas(names, "derby") || v76fHas(names, "shared") {
		t.Fatalf("heads %v %d: want derby (catalog-01) and pub-a (catalog-02), not shared", names, st)
	}
}

// Scenario 102: a partial reader whose block rule refers to /now ->
// GET /ns/matches/gestures/G -> 403.
func TestV076Scenario102(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	now := w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}})
	_, err := w.e.Gestures(context.Background(), "matches", "abcdefghijklmnopqrstuvwxyz", "", now)
	if v75Status(err) != 403 {
		t.Fatalf("%v, want 403", err)
	}
	if _, err := w.e.Gestures(context.Background(), "matches", "abcdefghijklmnopqrstuvwxyz", "", w.li()); err != nil {
		t.Fatalf("plain li: %v", err)
	}
}

// Scenario 109: at matches-r7's at, reader has not /principal/groups
// contains const "contractors", which matches has since removed; li is in
// contractors -> a filtered read of the branch keeps derby hidden through
// reader, and her gs keeps all her groups.
func TestV076Scenario109(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) {
		doc["roles"].(map[string]any)["reader"].(map[string]any)["rules"] = []any{map[string]any{"not": map[string]any{
			"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "contractors"}}}}}
	}})
	w.seed()
	ctx := context.Background()
	if _, err := w.e.CreateBranch(ctx, Request{NS: "matches", Cred: w.admin}, BranchRequest{Name: "matches-r7", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/roles/reader/rules"})
	li := w.catGrant("user:li", []any{"editors", "contractors"}, map[string]any{"ns": []any{"matches-r7"}})
	red, st := v76fRedirect(t, w, "matches-r7", "", li)
	if red == nil {
		t.Fatalf("li on the branch: %d", st)
	}
	names, st := v76fHeads(t, w, "matches-r7", red.GS, red.At, li)
	if st != 0 || v76fHas(names, "derby") {
		t.Fatalf("branch heads %v %d: derby must stay hidden", names, st)
	}
	// In matches itself, at its head, derby is visible.
	lim := w.catGrant("user:li", []any{"editors", "contractors"})
	red2, _ := v76fRedirect(t, w, "matches", "", lim)
	if red2 == nil {
		t.Fatal("matches")
	}
	if names, st := v76fHeads(t, w, "matches", red2.GS, red2.At, lim); st != 0 || !v76fHas(names, "derby") {
		t.Fatalf("matches heads %v %d", names, st)
	}
	// gs keeps all groups: li without contractors gets a different gs on
	// the branch.
	li2 := w.catGrant("user:li", []any{"editors"}, map[string]any{"ns": []any{"matches-r7"}})
	red3, _ := v76fRedirect(t, w, "matches-r7", "", li2)
	if red3 == nil || red3.GS == red.GS {
		t.Fatalf("gs of li without contractors %+v equals %s", red3, red.GS)
	}
}
