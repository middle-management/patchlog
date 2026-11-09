package core

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// V77-01 (v0.77): filtered coverage of purged catalogs (§B.11.9 Where) and
// a covered purged namespace's /heads without at (§B.11.9 Purged
// namespaces).

// v077Purge freezes and purges ns with the operator key.
func v077Purge(t *testing.T, w *v75World, ns string) string {
	t.Helper()
	w.patchConfig(ns, map[string]any{"op": "add", "path": "/frozen", "value": true})
	op := w.cred(w.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{ns}, "can": []any{"purge-ns"}})
	head := w.head(ns)
	if _, err := w.e.PurgeNamespace(context.Background(), Request{NS: ns, Cred: op}, head, true); err != nil {
		t.Fatal(err)
	}
	return w.head(ns)
}

// v077ConfigOnly reports whether every entry of a filtered log is a
// config entry, or a batch kept for its config entries alone.
func v077ConfigOnly(entries []map[string]any) bool {
	for _, e := range entries {
		switch e["kind"] {
		case "config":
		case "batch":
			items, _ := e["entries"].([]any)
			for _, it := range items {
				if m, _ := it.(map[string]any); m == nil || m["kind"] != "config" {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// §B.11.9 Where (scenario 115): "an end-to-end catalog, which the origin
// can't read, or a purged one, makes nothing visible". A namespace whose
// only trusted catalog is purged stays covered: its partial readers keep
// their filtered URLs and the exchange's /g/ prefix, and see nothing but
// config entries. Before v0.77 the purge uncovered it, every filtered
// read answering 403 "isn't read filtered here".
func TestV077OriginPurgedCatalogStaysCovered(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	// li's grant names cat-season's head before the purge, within maxLag.
	li := w.li()
	v077Purge(t, w, "cat-season")

	w.inTx(func(t2 *tx) {
		fs := t2.filteredScope(t2.nsByName("matches"))
		if fs == nil || fs.kind != fsContent || len(fs.cats) != 1 || !fs.cats[0].dark() {
			t.Fatalf("matches after its catalog's purge: %+v", fs)
		}
		if cp := t2.filteredCurrent(fs); len(cp.cats) != 0 {
			t.Fatalf("a purged catalog decides: %+v", cp.cats)
		}
		// The purged catalog itself is still covered, as a catalog.
		if cs := t2.filteredScope(t2.nsByName("cat-season")); cs == nil || cs.kind != fsCatalog {
			t.Fatalf("cat-season: %+v", cs)
		}
	})
	gs := v075GS(t, w, li)
	var fr *FilteredRedirect
	if err := w.e.FilteredCurrent(ctx, "matches", gs, "/heads", li); !errors.As(err, &fr) {
		t.Fatalf("FilteredCurrent /heads: %v, want a redirect", err)
	}
	page, _, err := w.e.FilteredHeads(ctx, "matches", gs, fr.At, "", "", li)
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("FilteredHeads: %+v %v, want no rows", page, err)
	}
	lg, _, err := w.e.FilteredLog(ctx, "matches", gs, fr.At, "", 1000, li)
	if err != nil || len(lg.Entries) == 0 || !v077ConfigOnly(lg.Entries) {
		t.Fatalf("FilteredLog: %+v %v, want config entries only", lg, err)
	}
	res, err := w.e.IssueEdgeGrants(ctx, []string{li.Bearer})
	if err != nil || len(res.Grants) != 1 {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	if got := res.Grants[0].Prefixes(); !reflect.DeepEqual(got, []string{"/ns/matches/g/" + gs}) {
		t.Fatalf("exchange prefixes %v, want the /g/ prefix", got)
	}
}

// §B.11.9 Branches: a dark catalog is skipped by the head-trust check, as
// an e2e one is, so a branch of a namespace whose catalog is purged stays
// covered.
func TestV077OriginPurgedCatalogBranchCovered(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	if _, err := w.e.CreateBranch(ctx, Request{NS: "matches", Cred: w.admin}, BranchRequest{Name: "matches-r7", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	v077Purge(t, w, "cat-season")
	w.inTx(func(t2 *tx) {
		fs := t2.filteredScope(t2.nsByName("matches-r7"))
		if fs == nil || fs.kind != fsBranch || len(fs.cats) != 1 || !fs.cats[0].dark() {
			t.Fatalf("matches-r7 after its root's catalog's purge: %+v", fs)
		}
	})
}

// §B.11.9 Purged namespaces: a covered purged namespace's /heads without
// at answers as §8.5 answers /heads, 410 purged with head, once the read
// check passes; never a 302 first. Without credentials it stays 401.
func TestV077OriginPurgedCoveredHeads(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	li := w.li()
	gs := v075GS(t, w, li)
	head := v077Purge(t, w, "matches")
	w.inTx(func(t2 *tx) {
		if fs := t2.filteredScope(t2.nsByName("matches")); fs == nil {
			t.Fatal("purged matches is no longer covered")
		}
	})
	err := w.e.FilteredCurrent(ctx, "matches", gs, "/heads", li)
	if e, _ := err.(*Error); e == nil || e.Status != 410 || e.Body["code"] != "purged" || e.Body["head"] != head {
		t.Fatalf("FilteredCurrent /heads: %v, want 410 purged with head %s", err, head)
	}
	if err := w.e.FilteredCurrent(ctx, "matches", gs, "/heads", Credentials{}); v75Status(err) != 401 {
		t.Fatalf("without credentials: %v, want 401", err)
	}
	// /log without at keeps the redirect: the range stays readable (§8.5).
	var fr *FilteredRedirect
	if err := w.e.FilteredCurrent(ctx, "matches", gs, "/log", li); !errors.As(err, &fr) {
		t.Fatalf("FilteredCurrent /log: %v, want a redirect", err)
	}
}
