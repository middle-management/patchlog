package core

import (
	"context"
	"testing"
	"time"
)

// §7.9 gs: a grant reading two covered namespaces with the same key
// rules and role definitions gets the same gs in both (a gs names no
// namespace), so filtered_gs keeps a row per (ns, gs): each namespace's
// cookie is admitted, by its own row.
func TestV075EngineGSPerNamespace(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	// results: matches's document, same key reader-01 and same roles.
	results := map[string]any{"read": "grant", "keys": []any{w.kEntry(), map[string]any{"kid": "reader-01", "alg": "ed25519", "pub": w.catPub,
		"can": []any{"read"}, "maxTtl": "PT15M",
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": v75Visible}}}},
		"roles": map[string]any{"reader": map[string]any{"can": []any{"read"}}}}
	w.mkNS("results", results)
	w.seed()
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
