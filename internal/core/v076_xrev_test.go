package core

import (
	"context"
	"testing"
	"time"
)

// Cross-review (conformance lens): scenario tests for the v0.76
// filtered-read scenarios that had none.

func v076XrevLog(t *testing.T, w *v75World, ns, vid, at string, cred Credentials) ([]map[string]any, int) {
	t.Helper()
	lg, _, err := w.e.FilteredLog(context.Background(), ns, vid, at, "", 0, cred)
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

// Scenario 95: a cookie for a view the origin keeps no row for -> 401.
func TestV076Scenario95(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	vid := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches", View: vid, Prefix: "/ns/matches/view/" + vid, Exp: w.now().Add(10 * time.Minute)}}
	err := w.e.FilteredCurrent(context.Background(), "matches", vid, "/heads", cookie)
	if v75Status(err) != 401 {
		t.Fatalf("%v, want 401", err)
	}
	if e, _ := err.(*Error); e == nil || e.Body["code"] != "unauthenticated" {
		t.Fatalf("%v, want unauthenticated", err)
	}
	// Contrast: a view the origin does keep a row for (li's, exchanged for
	// matches) is admitted, even with another namespace present.
	li := w.li()
	res, err := w.e.IssueEdgeGrants(context.Background(), []string{li.Bearer})
	if err != nil || len(res.Grants) != 1 {
		t.Fatal(res, err)
	}
	gs2 := res.Grants[0].View
	w.mkNS("other", map[string]any{"read": "grant", "keys": []any{w.kEntry()}})
	cookie2 := Credentials{Edge: &EdgeGrant{NS: "matches", View: gs2, Prefix: "/ns/matches/view/" + gs2, Exp: w.now().Add(10 * time.Minute)}}
	if err := w.e.FilteredCurrent(context.Background(), "matches", gs2, "/heads", cookie2); err == nil {
		t.Fatal("nil")
	} else if _, ok := err.(*FilteredRedirect); !ok {
		t.Fatalf("own vid: %v", err)
	}
}

// Scenario 96: matches removes the role li's view stored as effective ->
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
	vid := res.Grants[0].View
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches", View: vid, Prefix: "/ns/matches/view/" + vid, Exp: w.now().Add(10 * time.Minute)}}
	if red, st := v76fRedirect(t, w, "matches", vid, cookie); red == nil {
		t.Fatalf("before: %d", st)
	}
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/roles/viewer", "value": map[string]any{"can": []any{"read"}}},
		map[string]any{"op": "remove", "path": "/roles/reader"})
	if red, st := v76fRedirect(t, w, "matches", vid, cookie); st != 403 {
		t.Fatalf("after the role went: %+v %d, want 403", red, st)
	}
}

// Scenario 103: li at /ns/matches/view/{view}/heads of a view no exchange gave
// her -> 403; without credentials 401.
func TestV076Scenario103(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	li := w.cred(w.catPriv, map[string]any{"kid": "reader-01", "sub": "user:li", "groups": []any{"editors"}, "roles": []any{"reader"},
		"ns": []any{"matches"}, "can": []any{"read"}})
	vid := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if st := v75Status(w.e.FilteredCurrent(ctx, "matches", vid, "/heads", li)); st != 403 {
		t.Errorf("li: %d, want 403", st)
	}
	if st := v75Status(w.e.FilteredCurrent(ctx, "matches", vid, "/heads", Credentials{})); st != 401 {
		t.Errorf("no credentials: %d, want 401", st)
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
// contractors -> the branch isn't read filtered at all since v0.78
// (§7.9 Where: 403, no redirect).
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
	if _, st := v76fRedirect(t, w, "matches-r7", "", li); st != 403 {
		t.Fatalf("li on the branch: %d, want 403", st)
	}
	// In matches itself, at its head, derby is visible.
	lim := w.catGrant("user:li", []any{"editors", "contractors"})
	red2, _ := v76fRedirect(t, w, "matches", "", lim)
	if red2 == nil {
		t.Fatal("matches")
	}
	if names, st := v76fHeads(t, w, "matches", red2.View, red2.At, lim); st != 0 || !v76fHas(names, "derby") {
		t.Fatalf("matches heads %v %d", names, st)
	}

}
