package core

import (
	"context"
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
	id, err := w.e.PurgeNamespace(context.Background(), Request{NS: ns, Cred: op}, head, true)
	if err != nil {
		t.Fatal(err)
	}
	return id // the purge-ns entry's, all a purged namespace keeps but its name (§5)
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

// §7.9 Purged namespaces (v0.91): a covered purged namespace's /heads
// without at answers 410 purged with head, never a 302 first, whatever
// the grant: without credentials too, and its /log without at, which
// v0.90 still redirected to a readable range.
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
	err := w.e.FilteredCurrent(ctx, "matches", vid, "/heads", li)
	if e, _ := err.(*Error); e == nil || e.Status != 410 || e.Body["code"] != "purged" || e.Body["head"] != head {
		t.Fatalf("FilteredCurrent /heads: %v, want 410 purged with head %s", err, head)
	}
	if err := w.e.FilteredCurrent(ctx, "matches", vid, "/heads", Credentials{}); v75Status(err) != 410 {
		t.Fatalf("without credentials: %v, want 410", err)
	}
	v077PurgedHeads(t, w, "matches", vid, red.At, head, w.admin, true)
	v077PurgedHeads(t, w, "matches", vid, red.At, head, li, false)
	if err := w.e.FilteredCurrent(ctx, "matches", vid, "/log", li); v75Status(err) != 410 {
		t.Fatalf("FilteredCurrent /log: %v, want 410", err)
	}
}

// v077PurgedHeads checks that purged ns's filtered /heads for view, without
// at and at at, are each 410 purged with head for cred, and, where cred
// reads ns unrestricted, its unfiltered /heads too (§8.5, §7.9 Purged
// namespaces; v0.91).
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
	// v0.91 (§7.9 Purged namespaces, §8.5): 410 whatever the grant, an
	// unrestricted reader's in Authorization at a filtered URL included,
	// which v0.82 to v0.90 answered 403 there.
	purged("/view/{vid}/heads", w.e.FilteredCurrent(ctx, ns, vid, "/heads", cred))
	_, _, err := w.e.FilteredHeads(ctx, ns, vid, at, "", "", cred)
	purged("/view/{vid}/at/{at}/heads", err)
}
