package core

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// V81-02 (v0.78, v0.81): access in the core. A rule referring to /now
// never passes for a read (§C.2 item 5); a gs holds all the caller's
// groups and a stored "partial" set is refused (§B.11.5, §B.11.9 gs);
// filtered reads cover no branch, and a branch catalog is dark (§B.11.9
// Where).

// v081Heads are the names li's filtered /heads lists in matches, after
// following its redirect, and the redirect.
func v081Heads(t *testing.T, w *v75World, cred Credentials) ([]string, *FilteredRedirect) {
	t.Helper()
	red, st := v76fRedirect(t, w, "matches", "", cred)
	if red == nil {
		t.Fatalf("no redirect: %d", st)
	}
	names, st := v76fHeads(t, w, "matches", red.GS, red.At, cred)
	if st != 0 {
		t.Fatalf("filtered heads: %d", st)
	}
	return names, red
}

// §C.2 item 5 (ACCESS-1): wherever rules are evaluated for a read, one
// that refers to /now fails as a whole, under a not or an any too, as
// does one on the whole envelope; branching's unrestricted-read check
// (readsNS with stepOne) included. Writes keep now.
func TestV081AccessNowRulesFailReads(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	future := w.now().Add(time.Hour).UTC().Format(time.RFC3339)
	nowRules := map[string]any{
		"compare":        map[string]any{"op": "compare", "path": "/now", "lt": map[string]any{"value": future}},
		"not":            map[string]any{"not": map[string]any{"op": "compare", "path": "/now", "gt": map[string]any{"value": future}}},
		"any":            map[string]any{"any": []any{map[string]any{"op": "test", "path": "/now", "exists": true}, map[string]any{"op": "test", "path": "/action", "value": "read"}}},
		"whole envelope": map[string]any{"op": "test", "path": "", "schema": map[string]any{"type": "object"}},
	}
	for name, rule := range nowRules {
		g := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"matches"}, "can": []any{"read", "branch"}, "rules": []any{rule}})
		w.inTx(func(t2 *tx) {
			n := t2.nsByName("matches")
			cfg := t2.config(n.configSeq)
			a, err := t2.authenticate("matches", n, cfg, g, nil)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if t2.canRead(n, cfg, a, "derby") || t2.readsNS(n, cfg, a, false) || t2.readsNS(n, cfg, a, true) {
				t.Errorf("%s: the rule passes a read", name)
			}
			if _, err := t2.nsReader(n, g); err == nil || err.Status != 403 {
				t.Errorf("%s: nsReader %v, want 403", name, err)
			}
			if _, err := t2.reader(n, g, "derby"); err == nil || err.Status != 404 {
				t.Errorf("%s: reader %v, want 404", name, err)
			}
			if env := t2.basicEnvelope("read", "derby", a); env["now"] != nil {
				t.Errorf("a read envelope with now: %v", env)
			}
			if env := t2.basicEnvelope("append", "derby", a); env["now"] == nil {
				t.Errorf("a write envelope without now: %v", env)
			}
		})
	}
	// A role with such a rule doesn't count for read; another role does.
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/roles/clock",
		"value": map[string]any{"can": []any{"read"}, "rules": []any{nowRules["not"]}}})
	clock := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"matches"}, "can": []any{"read"}, "roles": []any{"clock"}})
	both := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"matches"}, "can": []any{"read"}, "roles": []any{"clock", "reader"}})
	w.inTx(func(t2 *tx) {
		n := t2.nsByName("matches")
		if _, err := t2.nsReader(n, clock); err == nil || err.Status != 403 {
			t.Errorf("clock alone: %v, want 403", err)
		}
		if _, err := t2.nsReader(n, both); err != nil {
			t.Errorf("clock and reader: %v", err)
		}
	})
}

// §B.11.9 Partial reader, §A.4 gs (ACCESS-4): a role with a rule on /now
// just doesn't count. li, with roles clock (/now) and prefixed (/resource
// ^pub-), reads matches filtered through prefixed alone; once prefixed
// gains a /now rule, her cookie is 403 (the stored role's digest no longer
// holds) and she is no partial reader. Before v0.78 the /now role made
// her unreadable this way (403).
func TestV081AccessNowRoleDropsOut(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) {
		delete(doc["keys"].([]any)[1].(map[string]any), "rules")
		roles := doc["roles"].(map[string]any)
		roles["clock"] = map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}}
		roles["prefixed"] = map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^pub-"}}}}
	}})
	w.seed()
	w.put("cat-season", "matches.pub-a", map[string]any{"parents": v75Parents("season")})
	w.put("matches", "pub-a", map[string]any{"title": "pub-a"})
	ctx := context.Background()
	li := w.li(map[string]any{"roles": []any{"clock", "prefixed"}})
	names, red := v081Heads(t, w, li)
	if !slices.Equal(names, []string{"pub-a"}) {
		t.Fatalf("li's filtered heads %v, want pub-a alone", names)
	}
	res, err := w.e.IssueEdgeGrants(ctx, []string{li.Bearer})
	if err != nil || len(res.Grants) != 1 || res.Grants[0].GS != red.GS {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	w.inTx(func(t2 *tx) {
		r := t2.loadGS("matches", red.GS)
		if r == nil || !slices.Equal(r.roles, []string{"prefixed"}) {
			t.Fatalf("stored row %+v, want roles [prefixed]", r)
		}
	})
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches", GS: red.GS, Prefix: "/ns/matches/g/" + red.GS, Exp: w.now().Add(10 * time.Minute)}}
	if names, st := v76fHeads(t, w, "matches", red.GS, red.At, cookie); st != 0 || !slices.Equal(names, []string{"pub-a"}) {
		t.Fatalf("cookie: %v %d", names, st)
	}
	// Only clock: no role counts, so no read.
	if _, st := v76fRedirect(t, w, "matches", "", w.li(map[string]any{"roles": []any{"clock"}})); st != 403 {
		t.Fatalf("clock alone: %d, want 403", st)
	}
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/roles/prefixed/rules/-",
		"value": map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}})
	if _, st := v76fRedirect(t, w, "matches", red.GS, cookie); st != 403 {
		t.Fatalf("the old cookie after prefixed gained a /now rule: %d, want 403", st)
	}
	if _, st := v76fRedirect(t, w, "matches", "", li); st != 403 {
		t.Fatalf("li after prefixed gained a /now rule: %d, want 403", st)
	}
}

// TDA 78 and 69 (§B.11.5, §B.11.9 gs; ACCESS-5): a gs holds every group
// of the caller. Two readers whose groups differ only in one nothing
// names get different gs; and li's old cookie, whose gs holds interns,
// shows derby hidden at once once reader gains not /principal/groups
// contains "interns". Before v0.78 groups nothing named were left out
// ("partial"), and both readers shared a gs.
func TestV081AccessGSAllGroups(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	gs := func(cred Credentials) (string, []string) {
		var gs string
		var subs []string
		w.inTx(func(t2 *tx) {
			fv := v075View(t, t2, "matches", cred)
			gs, subs = fv.GS(), fv.subjects
		})
		return gs, subs
	}
	a, aSubs := gs(w.catGrant("user:bo", []any{"editors", "interns"}))
	b, bSubs := gs(w.catGrant("user:bo", []any{"editors", "contractors"}))
	if a == b || !slices.Contains(aSubs, "group:interns") || !slices.Contains(bSubs, "group:contractors") || slices.Contains(aSubs, "partial") {
		t.Fatalf("bo's subject sets %v and %v share gs %s", aSubs, bSubs, a)
	}
	// li, without roles in her grant, so that reader's rules aren't in her
	// scope digest: item 1 judges them per subject set.
	li := w.cred(w.catPriv, map[string]any{"kid": "catalog-01", "sub": "user:li", "groups": []any{"editors", "interns"}, "ns": []any{"matches"},
		"can": []any{"read"}, "at": map[string]any{"ns": "cat-season", "id": w.head("cat-season")},
		"exp": w.now().Add(10 * time.Minute).UTC().Format(time.RFC3339)})
	names, red := v081Heads(t, w, li)
	if !slices.Contains(names, "derby") {
		t.Fatalf("li's heads %v", names)
	}
	res, err := w.e.IssueEdgeGrants(ctx, []string{li.Bearer})
	if err != nil || len(res.Grants) != 1 || res.Grants[0].GS != red.GS {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches", GS: red.GS, Prefix: "/ns/matches/g/" + red.GS, Exp: w.now().Add(10 * time.Minute)}}
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/roles/reader/rules", "value": []any{map[string]any{"not": map[string]any{
		"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "interns"}}}}}})
	red2, st := v76fRedirect(t, w, "matches", red.GS, cookie)
	if red2 == nil || red2.At == red.At {
		t.Fatalf("the old cookie at a later at: %+v %d", red2, st)
	}
	if names, st := v76fHeads(t, w, "matches", red.GS, red2.At, cookie); st != 0 || slices.Contains(names, "derby") {
		t.Fatalf("the old cookie at a later at: %v %d, want derby hidden", names, st)
	}
}

// §B.11.9 gs (ACCESS-6): a stored subject set marked partial, as before
// v0.78, is always refused, 403 "exchange again", whatever the catalogs
// decide: never served as a set that leaves groups out. So is one whose
// subjects hold "partial" without the column.
func TestV081AccessStoredPartialRefused(t *testing.T) {
	t.Parallel()
	for _, set := range []string{`partial = 1`, `subjects = '["group:editors","partial"]'`} {
		w := newV75World(t, v75Opts{})
		w.seed()
		ctx := context.Background()
		li := w.li()
		res, err := w.e.IssueEdgeGrants(ctx, []string{li.Bearer})
		if err != nil || len(res.Grants) != 1 || res.Grants[0].GS == "" {
			t.Fatalf("exchange: %+v %v", res, err)
		}
		gs := res.Grants[0].GS
		cookie := Credentials{Edge: &EdgeGrant{NS: "matches", GS: gs, Prefix: "/ns/matches/g/" + gs, Exp: w.now().Add(10 * time.Minute)}}
		red, st := v76fRedirect(t, w, "matches", gs, cookie)
		if red == nil {
			t.Fatalf("cookie before: %d", st)
		}
		if err := w.e.update(ctx, func(t2 *tx) error {
			_, err := t2.Exec(`UPDATE filtered_gs SET `+set+` WHERE ns = ? AND gs = ?`, "matches", gs)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		_, _, err = w.e.FilteredHeads(ctx, "matches", gs, red.At, "", "", cookie)
		var e *Error
		if !errors.As(err, &e) || e.Status != 403 {
			t.Fatalf("%s: %v, want 403", set, err)
		}
		if _, st := v76fRedirect(t, w, "matches", gs, cookie); st != 403 {
			t.Fatalf("%s: FilteredCurrent %d, want 403", set, st)
		}
	}
}

// §B.11.9 Where (ACCESS-8): a trusted catalog that is a local branch makes
// nothing visible. matches names cat-br, a branch of cat-season whose
// catalog.trust lists matches, through a requireAt cat-br key: matches
// stays covered, cat-br is in no checkpoint, and li's filtered /heads
// lists nothing, her log only config entries.
func TestV081AccessBranchCatalogDark(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	w.admin = w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"cat-season", "cat-br", "matches"},
		"can": []any{"read", "create", "append", "delete", "restore", "purge", "config", "branch"}})
	if _, err := w.e.CreateBranch(ctx, Request{NS: "cat-season", Cred: w.admin}, BranchRequest{Name: "cat-br", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	w.patchConfig("matches",
		map[string]any{"op": "replace", "path": "/catalogs", "value": map[string]any{"cat-br": map[string]any{"place": []any{}}}},
		map[string]any{"op": "replace", "path": "/keys/1/requireAt", "value": "cat-br"})
	w.inTx(func(t2 *tx) {
		fs := t2.filteredScope(t2.nsByName("matches"))
		if fs == nil || len(fs.cats) != 1 || fs.cats[0].n.name != "cat-br" || !fs.cats[0].dark() {
			t.Fatalf("matches: %+v", fs)
		}
		if cp := t2.filteredCurrent(fs); len(cp.cats) != 0 || cp.ids["cat-br"] != "" {
			t.Fatalf("a branch catalog in the checkpoint: %v", cp.ids)
		}
		if fs := t2.filteredScope(t2.nsByName("cat-br")); fs != nil {
			t.Fatalf("cat-br covered: %+v", fs)
		}
	})
	li := w.cred(w.catPriv, map[string]any{"kid": "catalog-01", "sub": "user:li", "groups": []any{"editors"}, "roles": []any{"reader"},
		"ns": []any{"matches"}, "can": []any{"read"}, "at": map[string]any{"ns": "cat-br", "id": w.head("cat-br")},
		"exp": w.now().Add(10 * time.Minute).UTC().Format(time.RFC3339)})
	names, red := v081Heads(t, w, li)
	if len(names) != 0 {
		t.Fatalf("li's heads through a branch catalog: %v", names)
	}
	lg, _, err := w.e.FilteredLog(ctx, "matches", red.GS, red.At, "", 1000, li)
	if err != nil || len(lg.Entries) == 0 || !v077ConfigOnly(lg.Entries) {
		t.Fatalf("li's log through a branch catalog: %+v %v", lg, err)
	}
}

// §7.4 (BYTES-2): decorateNSEntry gives the chain's first entry prev "",
// and every later one the id before it.
func TestV081AccessFirstPrev(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	lg, err := w.e.NamespaceLog(context.Background(), "matches", w.head("matches"), "", 1000, w.admin)
	if err != nil || len(lg.Entries) == 0 {
		t.Fatalf("%+v %v", lg, err)
	}
	if p, ok := lg.Entries[0]["prev"]; !ok || p != "" {
		t.Fatalf("first entry %v: prev %v %v", lg.Entries[0], p, ok)
	}
	for i := 1; i < len(lg.Entries); i++ {
		if lg.Entries[i]["prev"] != lg.Entries[i-1]["id"] {
			t.Fatalf("entry %d: prev %v, want %v", i, lg.Entries[i]["prev"], lg.Entries[i-1]["id"])
		}
	}
}
