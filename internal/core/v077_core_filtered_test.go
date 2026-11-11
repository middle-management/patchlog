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

// §B.11.9 Where (v0.78: "Filtered reads cover no branch"): a branch of a
// namespace whose catalog is purged isn't covered either. Before v0.78 a
// dark catalog was skipped by the head-trust check and the branch stayed
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
		if fs := t2.filteredScope(t2.nsByName("matches-r7")); fs != nil {
			t.Fatalf("matches-r7 after its root's catalog's purge: %+v", fs)
		}
		if fs := t2.filteredScope(t2.nsByName("matches")); fs == nil || !fs.cats[0].dark() {
			t.Fatalf("matches after its catalog's purge: %+v", fs)
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
	red, st := v76fRedirect(t, w, "matches", gs, li)
	if red == nil {
		t.Fatalf("matches before its purge: %d", st)
	}
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
	// An unrestricted reader passes §8.5's read check at its unfiltered
	// /heads, 410; at this URL its grant is 403, as at a filtered URL that
	// serves rows ("reads unrestricted"), with or without at (v0.82;
	// before, 410 here too).
	v077PurgedHeads(t, w, "matches", gs, red.At, head, w.admin, true)
	v077PurgedHeads(t, w, "matches", gs, red.At, head, li, false)
	// /log without at keeps the redirect: the range stays readable (§8.5).
	var fr *FilteredRedirect
	if err := w.e.FilteredCurrent(ctx, "matches", gs, "/log", li); !errors.As(err, &fr) {
		t.Fatalf("FilteredCurrent /log: %v, want a redirect", err)
	}
}

// v077PurgedHeads checks that purged ns's filtered /heads for gs, without
// at and at at, are each 410 purged with head for a partial reader's
// cred; where cred reads ns unrestricted, that its unfiltered /heads is
// that 410 and the filtered ones 403 (§8.5, §B.11.9 Purged namespaces,
// Partial reader; v0.82).
func v077PurgedHeads(t *testing.T, w *v75World, ns, gs, at, head string, cred Credentials, unrestricted bool) {
	t.Helper()
	ctx := context.Background()
	purged := func(what string, err error) {
		t.Helper()
		if e, _ := err.(*Error); e == nil || e.Status != 410 || e.Body["code"] != "purged" || e.Body["head"] != head {
			t.Fatalf("%s of purged %s: %v, want 410 purged with head %s", what, ns, err, head)
		}
	}
	if unrestricted {
		_, err := w.e.NamespaceHeadsPrefix(ctx, ns, head, "", "", cred)
		purged("/heads", err)
	}
	if unrestricted {
		// v0.82 (§B.11.9 Purged namespaces, Partial reader): the filtered
		// URL's read check comes first, and an unrestricted reader's
		// grant in Authorization is 403 there, as at a live namespace's.
		if err := w.e.FilteredCurrent(ctx, ns, gs, "/heads", cred); v75Status(err) != 403 {
			t.Fatalf("/g/{gs}/heads of purged %s for an unrestricted grant: %v, want 403", ns, err)
		}
		if _, _, err := w.e.FilteredHeads(ctx, ns, gs, at, "", "", cred); v75Status(err) != 403 {
			t.Fatalf("/g/{gs}/at/{at}/heads of purged %s for an unrestricted grant: %v, want 403", ns, err)
		}
		return
	}
	purged("/g/{gs}/heads", w.e.FilteredCurrent(ctx, ns, gs, "/heads", cred))
	_, info, err := w.e.FilteredHeads(ctx, ns, gs, at, "", "", cred)
	purged("/g/{gs}/at/{at}/heads", err)
	if info == nil || info.GS != gs || info.At == "" {
		t.Fatalf("/g/{gs}/at/{at}/heads of purged %s: info %+v, want the checkpoint", ns, info)
	}
}

// §B.11.9 Purged namespaces, §8.5: purged cat-season stays covered as a
// catalog; its filtered /heads answers as its /heads, 410 purged once the
// URL's read check passes: for a partial reader at its own gs, while its
// unrestricted reader's grant is 403 there (v0.82) and gets the 410 at
// the unfiltered /heads. Without credentials it is 401.
func TestV077OriginPurgedCatalogHeads(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	cr := w.catReader("user:li", "editors")
	red, st := v76fRedirect(t, w, "cat-season", "", cr)
	if red == nil {
		t.Fatalf("cat-season: %d", st)
	}
	head := v077Purge(t, w, "cat-season")
	v077PurgedHeads(t, w, "cat-season", red.GS, red.At, head, w.admin, true)
	// The purge leaves cat-season out of its own deciding views, so its
	// partial reader's subject set changes: it is redirected to its own
	// (§B.11.9 gs), where it gets 410 as well.
	_, err := v76fUnfiltered(ctx, w.e, "cat-season", cr)
	now, _ := err.(*FilteredRedirect)
	if now == nil {
		t.Fatalf("purged cat-season's unfiltered URL for its partial reader: %v, want a redirect", err)
	}
	v077PurgedHeads(t, w, "cat-season", now.GS, now.At, head, cr, false)
	if err := w.e.FilteredCurrent(ctx, "cat-season", red.GS, "/heads", Credentials{}); v75Status(err) != 401 {
		t.Fatalf("without credentials: %v, want 401", err)
	}
}
