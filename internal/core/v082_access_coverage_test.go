package core

import (
	"context"
	"slices"
	"testing"
)

// V82-02 (v0.82), ACC-9o: purged catalogs and purged namespaces in
// coverage (SERVICES §B.11.9 Where; conformance 123, 124).

// v82accessDocsWorld is a v75World whose cat-season also trusts docs, a
// private namespace with its own catalog key, whose scope has no rules,
// so that it counts for folders (§B.11.5), and a role docsreader that
// only docs defines. Folder f gives group fans docsreader, with
// inheritance off, and holds placements of docs's guide and of matches's
// derby2. fa, in fans, is a partial reader of cat-season and of matches.
func v82accessDocsWorld(t *testing.T) (w *v75World, catFa, matchesFa func() Credentials) {
	t.Helper()
	w = newV75World(t, v75Opts{cat: func(doc map[string]any) {
		doc["catalog"] = map[string]any{"trust": []any{"matches", "docs"}}
	}})
	w.mkNS("docs", map[string]any{"read": "grant", "keys": []any{w.kEntry(), map[string]any{"kid": "docs-cat", "alg": "ed25519", "pub": w.catPub,
		"can": []any{"read"}, "requireAt": "cat-season", "maxTtl": "PT15M"}},
		"roles":    map[string]any{"docsreader": map[string]any{"can": []any{"read"}}},
		"catalogs": map[string]any{"cat-season": map[string]any{"place": []any{}}}})
	w.admin = w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"cat-season", "matches", "docs"},
		"can": []any{"read", "create", "append", "delete", "restore", "purge", "config", "branch"}})
	w.seed()
	w.put("cat-season", "f", map[string]any{"parents": v75Parents("root"), "$access": map[string]any{"inherit": false, "group:fans": []any{"docsreader"}}})
	w.put("cat-season", "docs.guide", map[string]any{"parents": v75Parents("f")})
	w.put("cat-season", "matches.derby2", map[string]any{"parents": v75Parents("f")})
	w.put("docs", "guide", map[string]any{"title": "guide"})
	w.put("matches", "derby2", map[string]any{"title": "derby2"})
	catFa = func() Credentials { return w.catReader("user:fa", "fans") }
	matchesFa = func() Credentials { return w.catGrant("user:fa", []any{"fans"}) }
	return w, catFa, matchesFa
}

// v82accessNames are the names cred's filtered /heads of ns lists, through
// its redirect from the unfiltered URL; st is the redirect's refusal.
func v82accessNames(t *testing.T, w *v75World, ns string, cred Credentials) (names []string, st int) {
	t.Helper()
	red, st := v76fRedirect(t, w, ns, "", cred)
	if red == nil {
		return nil, st
	}
	names, st = v76fHeads(t, w, ns, red.GS, red.At, cred)
	return names, st
}

// Conformance 123 at the origin (§B.11.9 Where: "Only such namespaces'
// roles count for that catalog's folders. ... A purged namespace's roles
// count for no catalog's folders"): private docs, whose docsreader role
// alone made folder f visible to fa, is purged. cat-season's filtered
// /heads then hides f and what it holds from fa; before the purge it
// showed them. Nothing of matches becomes or stays visible through the
// purged namespace's role either.
func TestV082AccessPurgedNamespaceRolesCountForNoFolder(t *testing.T) {
	t.Parallel()
	w, catFa, matchesFa := v82accessDocsWorld(t)
	names, st := v82accessNames(t, w, "cat-season", catFa())
	if st != 0 || !slices.Contains(names, "f") || !slices.Contains(names, "docs.guide") {
		t.Fatalf("cat-season for fa before the purge: %v %d, want f and docs.guide", names, st)
	}
	// matches doesn't define docsreader: f's entry gives fa nothing there.
	before, st := v82accessNames(t, w, "matches", matchesFa())
	if st != 0 || slices.Contains(before, "derby2") {
		t.Fatalf("matches for fa before the purge: %v %d, want no derby2", before, st)
	}
	// fa's catalog grant is minted before the purge, so only the purge
	// changes what it shows.
	fa := catFa()
	v077Purge(t, w, "docs")
	names, st = v82accessNames(t, w, "cat-season", fa)
	if st != 0 {
		t.Fatalf("cat-season for fa after the purge: %d", st)
	}
	for _, hidden := range []string{"f", "docs.guide", "matches.derby2"} {
		if slices.Contains(names, hidden) {
			t.Errorf("cat-season for fa after docs's purge still lists %s: %v", hidden, names)
		}
	}
	if after, st := v82accessNames(t, w, "matches", matchesFa()); st != 0 || slices.Contains(after, "derby2") || !slices.Equal(after, before) {
		t.Errorf("matches for fa after docs's purge: %v %d, want %v", after, st, before)
	}
	// The purged namespace is in no checkpoint, and still covered itself,
	// through its last stored document (conformance 124 calls a purged
	// namespace covered, with a gs).
	w.inTx(func(t2 *tx) {
		cs := t2.filteredScope(t2.nsByName("cat-season"))
		if cs == nil {
			t.Fatal("cat-season is no longer covered: matches still trusts it")
		}
		if cp := t2.filteredCurrent(cs); cp.ids["docs"] != "" {
			t.Errorf("purged docs is a member of cat-season's checkpoint: %v", cp.ids)
		}
		if ds := t2.filteredScope(t2.nsByName("docs")); ds == nil || ds.kind != fsContent {
			t.Errorf("purged docs: %+v, want covered still", ds)
		}
	})
}

// §B.11.9 Where: "It covers ... a namespace that trusts a catalog, and
// that catalog", and a purged namespace's roles count for no folder: a
// catalog whose only trusting namespace is purged is covered through
// none, so its partial reader's URLs answer as an uncovered namespace's
// (403, no redirect), while the purged namespace stays covered and a
// purged catalog keeps covering by its last stored catalog.trust.
func TestV082AccessCatalogOfPurgedNamespaceOnly(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	cr := w.catReader("user:li", "editors")
	red, st := v76fRedirect(t, w, "cat-season", "", cr)
	if red == nil {
		t.Fatalf("cat-season before: %d", st)
	}
	v077Purge(t, w, "matches")
	w.inTx(func(t2 *tx) {
		if cs := t2.filteredScope(t2.nsByName("cat-season")); cs != nil {
			t.Errorf("cat-season, trusted by purged matches alone: %+v, want uncovered", cs)
		}
		ms := t2.filteredScope(t2.nsByName("matches"))
		if ms == nil || len(ms.cats) != 1 || ms.cats[0].n.name != "cat-season" {
			t.Errorf("purged matches: %+v, want covered through cat-season", ms)
		}
	})
	if _, err := v76fUnfiltered(ctx, w.e, "cat-season", cr); v75Status(err) != 403 {
		t.Errorf("cat-season's unfiltered URL for its partial reader: %v, want 403", err)
	}
	if err := w.e.FilteredCurrent(ctx, "cat-season", red.GS, "/heads", cr); v75Status(err) != 403 {
		t.Errorf("cat-season's filtered /heads: %v, want 403", err)
	}
	if _, _, err := w.e.FilteredHeads(ctx, "cat-season", red.GS, red.At, "", "", cr); v75Status(err) != 403 {
		t.Errorf("cat-season's filtered /heads at the earlier at: %v, want 403", err)
	}
}
