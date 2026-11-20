package core

import (
	"context"
	"errors"
	"testing"
)

// V77-01 (v0.77): a covered purged namespace's /heads without at (§7.9 Purged
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

// §7.9 Purged namespaces: a covered purged namespace's /heads without
// at answers as §8.5 answers /heads, 410 purged with head, once the read
// check passes; never a 302 first. Without credentials it stays 401.
func TestV077OriginPurgedCoveredHeads(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	li := w.li()
	vid := v075ViewID(t, w, li)
	red, st := v76fRedirect(t, w, "matches", vid, li)
	if red == nil {
		t.Fatalf("matches before its purge: %d", st)
	}
	head := v077Purge(t, w, "matches")
	w.inTx(func(t2 *tx) {
		if fs := t2.filteredScope(t2.nsByName("matches")); fs == nil {
			t.Fatal("purged matches is no longer covered")
		}
	})
	err := w.e.FilteredCurrent(ctx, "matches", vid, "/heads", li)
	if e, _ := err.(*Error); e == nil || e.Status != 410 || e.Body["code"] != "purged" || e.Body["head"] != head {
		t.Fatalf("FilteredCurrent /heads: %v, want 410 purged with head %s", err, head)
	}
	if err := w.e.FilteredCurrent(ctx, "matches", vid, "/heads", Credentials{}); v75Status(err) != 401 {
		t.Fatalf("without credentials: %v, want 401", err)
	}
	// An unrestricted reader passes §8.5's read check at its unfiltered
	// /heads, 410; at this URL its grant is 403, as at a filtered URL that
	// serves rows ("reads unrestricted"), with or without at (v0.82;
	// before, 410 here too).
	v077PurgedHeads(t, w, "matches", vid, red.At, head, w.admin, true)
	v077PurgedHeads(t, w, "matches", vid, red.At, head, li, false)
	// /log without at keeps the redirect: the range stays readable (§8.5).
	var fr *FilteredRedirect
	if err := w.e.FilteredCurrent(ctx, "matches", vid, "/log", li); !errors.As(err, &fr) {
		t.Fatalf("FilteredCurrent /log: %v, want a redirect", err)
	}
}

// v077PurgedHeads checks that purged ns's filtered /heads for view, without
// at and at at, are each 410 purged with head for a partial reader's
// cred; where cred reads ns unrestricted, that its unfiltered /heads is
// that 410 and the filtered ones 403 (§8.5, §7.9 Purged namespaces,
// Partial reader; v0.82).
func v077PurgedHeads(t *testing.T, w *v75World, ns, vid, at, head string, cred Credentials, unrestricted bool) {
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
		// v0.82 (§7.9 Purged namespaces, Partial reader): the filtered
		// URL's read check comes first, and an unrestricted reader's
		// grant in Authorization is 403 there, as at a live namespace's.
		if err := w.e.FilteredCurrent(ctx, ns, vid, "/heads", cred); v75Status(err) != 403 {
			t.Fatalf("/view/{vid}/heads of purged %s for an unrestricted grant: %v, want 403", ns, err)
		}
		if _, _, err := w.e.FilteredHeads(ctx, ns, vid, at, "", "", cred); v75Status(err) != 403 {
			t.Fatalf("/view/{vid}/at/{at}/heads of purged %s for an unrestricted grant: %v, want 403", ns, err)
		}
		return
	}
	purged("/view/{vid}/heads", w.e.FilteredCurrent(ctx, ns, vid, "/heads", cred))
	_, info, err := w.e.FilteredHeads(ctx, ns, vid, at, "", "", cred)
	purged("/view/{vid}/at/{at}/heads", err)
	if info == nil || info.View != vid || info.At == "" {
		t.Fatalf("/view/{vid}/at/{at}/heads of purged %s: info %+v, want the checkpoint", ns, info)
	}
}
