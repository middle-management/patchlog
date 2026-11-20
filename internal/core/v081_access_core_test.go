package core

import (
	"context"
	"slices"
	"testing"
	"time"
)

// V81-02 (v0.78, v0.81): access in the core. A rule referring to /now
// never passes for a read (§C.2 item 5); a view holds all the caller's
// groups and a stored "partial" set is refused (§B.11.5, §7.9 view);
// filtered reads cover no branch (§7.9 Where).

// v081Heads are the names li's filtered /heads lists in matches, after
// following its redirect, and the redirect.
func v081Heads(t *testing.T, w *v75World, cred Credentials) ([]string, *FilteredRedirect) {
	t.Helper()
	red, st := v76fRedirect(t, w, "matches", "", cred)
	if red == nil {
		t.Fatalf("no redirect: %d", st)
	}
	names, st := v76fHeads(t, w, "matches", red.View, red.At, cred)
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

// §7.9 Partial reader, §A.4 view (ACCESS-4): a role with a rule on /now
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
	if err != nil || len(res.Grants) != 1 || res.Grants[0].View != red.View {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	w.inTx(func(t2 *tx) {
		r := t2.loadView("matches", red.View)
		if r == nil || !slices.Equal(r.roles, []string{"prefixed"}) {
			t.Fatalf("stored row %+v, want roles [prefixed]", r)
		}
	})
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches", View: red.View, Prefix: "/ns/matches/view/" + red.View, Exp: w.now().Add(10 * time.Minute)}}
	if names, st := v76fHeads(t, w, "matches", red.View, red.At, cookie); st != 0 || !slices.Equal(names, []string{"pub-a"}) {
		t.Fatalf("cookie: %v %d", names, st)
	}
	// Only clock: no role counts, so no read.
	if _, st := v76fRedirect(t, w, "matches", "", w.li(map[string]any{"roles": []any{"clock"}})); st != 403 {
		t.Fatalf("clock alone: %d, want 403", st)
	}
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/roles/prefixed/rules/-",
		"value": map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}})
	if _, st := v76fRedirect(t, w, "matches", red.View, cookie); st != 403 {
		t.Fatalf("the old cookie after prefixed gained a /now rule: %d, want 403", st)
	}
	if _, st := v76fRedirect(t, w, "matches", "", li); st != 403 {
		t.Fatalf("li after prefixed gained a /now rule: %d, want 403", st)
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
