package core

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/catvis"
)

// §B.11.9 gs: a grant reading two covered namespaces with the same key
// rules and role definitions gets the same gs in both (a gs names no
// namespace), so filtered_gs keeps a row per (ns, gs): each namespace's
// cookie is admitted, by its own row.
func TestV075EngineGSPerNamespace(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{cat: func(doc map[string]any) {
		doc["catalog"] = map[string]any{"trust": []any{"matches", "results"}}
	}})
	// results: matches's document, same key catalog-01 and same roles.
	results := map[string]any{"read": "grant", "keys": []any{w.kEntry(), map[string]any{"kid": "catalog-01", "alg": "ed25519", "pub": w.catPub,
		"can": []any{"read"}, "requireAt": "cat-season", "maxTtl": "PT15M",
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}}},
		"roles":    map[string]any{"reader": map[string]any{"can": []any{"read"}}},
		"catalogs": map[string]any{"cat-season": map[string]any{"place": []any{}}}}
	w.mkNS("results", results)
	w.seed()
	w.put("cat-season", "results.derby", map[string]any{"parents": v75Parents("season")})
	admin := w.admin
	w.admin = w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"results"}, "can": []any{"read", "create", "append"}})
	w.put("results", "derby", map[string]any{"title": "derby"})
	w.admin = admin

	li := w.li(map[string]any{"ns": []any{"matches", "results"}})
	res, err := w.e.IssueEdgeGrants(context.Background(), []string{li.Bearer})
	if err != nil || len(res.Grants) != 2 {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	if res.Grants[0].GS != res.Grants[1].GS {
		t.Fatalf("gs matches=%s results=%s: the case needs them equal", res.Grants[0].GS, res.Grants[1].GS)
	}
	exp := w.now().Add(10 * time.Minute)
	for _, g := range res.Grants {
		cred := Credentials{Edge: &EdgeGrant{NS: g.NS, GS: g.GS, Prefix: "/ns/" + g.NS + "/g/" + g.GS, Exp: exp}}
		w.inTx(func(t2 *tx) {
			n := t2.nsByName(g.NS)
			fs := t2.filteredScope(n)
			if _, err := t2.filteredAdmit(n, fs, g.GS, t2.filteredCurrent(fs), cred); err != nil {
				t.Errorf("%s: the cookie just issued for /ns/%s/g/%s is refused: %d %v", g.NS, g.NS, g.GS, err.Status, err.Body)
			}
			if r := t2.loadGS(g.NS, g.GS); r == nil || r.ns != g.NS {
				t.Errorf("%s: filtered_gs row %+v", g.NS, r)
			}
		})
	}
}

// §B.11.9 Catalogs never show a placement whose item doesn't exist or is
// tombstoned, and a node's own tombstone reaches exactly those who could
// see it live (Deleted resources): the tombstone of a placement hidden
// while live, because its item never existed or was tombstoned, stays
// hidden, and so does its name.
func TestV075EngineCatalogTombstoneOfDanglingPlacement(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{
		matches: func(doc map[string]any) { delete(doc["keys"].([]any)[1].(map[string]any), "rules") },
	})
	w.seed()
	w.put("cat-season", "matches.gone", map[string]any{"parents": v75Parents("season")})
	li := w.catReader("user:li", "editors")
	if got := v075Visible(t, w, "cat-season", li, "matches.gone", "matches.shared"); got["matches.gone"] || !got["matches.shared"] {
		t.Fatalf("live: %v", got)
	}
	// shared's item is tombstoned: its live placement is hidden.
	w.del("matches", "shared")
	if got := v075Visible(t, w, "cat-season", li, "matches.shared"); got["matches.shared"] {
		t.Fatalf("placement of a tombstoned item: %v", got)
	}
	w.del("cat-season", "matches.gone")
	w.del("cat-season", "matches.shared")
	got := v075Visible(t, w, "cat-season", li, "matches.gone", "matches.shared")
	if got["matches.gone"] {
		t.Errorf("the tombstone of matches.gone, a placement hidden while live (its item never existed), is visible")
	}
	if got["matches.shared"] {
		t.Errorf("the tombstone of matches.shared, hidden while live (its item tombstoned), is visible")
	}
}

// A deleted catalog node's tombstone reaches those who could see it live
// (§B.11.9 Deleted resources, Catalogs), through its own $access too: the
// group only that $access named keeps deciding, so the reader's gs keeps
// it.
func TestV075EngineTombstoneVisibleThroughItsOwnAccess(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{
		matches: func(doc map[string]any) { delete(doc["keys"].([]any)[1].(map[string]any), "rules") },
	})
	w.seed()
	w.put("cat-season", "audit", map[string]any{"parents": v75Parents("root"), "$access": map[string]any{"group:auditors": []any{"reader"}}})
	bo := w.catReader("user:bo", "auditors")
	if got := v075Visible(t, w, "cat-season", bo, "audit", "root"); !got["audit"] || got["root"] {
		t.Fatalf("live: %v", got)
	}
	w.del("cat-season", "audit")
	if got := v075Visible(t, w, "cat-season", bo, "audit"); !got["audit"] {
		t.Errorf("the tombstone of audit, visible to bo while live, is hidden from bo")
	}
	w.inTx(func(t2 *tx) {
		if subs := v075View(t, t2, "cat-season", bo).subjects; !slices.Contains(subs, "group:auditors") || slices.Contains(subs, catvis.Partial) {
			t.Errorf("bo's subjects after the delete: %v", subs)
		}
	})
}
