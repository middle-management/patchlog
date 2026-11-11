package core

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// BT-4 (§G.5.1 access, §2.1): archiveAccess is a namespace's protection
// as a source by its own document: e2e, else sealed whatever its read,
// else public or private by its read. A branch's is its own, not its
// base's (a branch writes no archive today, §8.6 "Branches don't prune",
// so only this function says so).
func TestV082ToolsArchiveAccessOf(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}, KeyStore: ks})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	ctx := context.Background()
	enc := func(read, level string) map[string]any {
		doc := map[string]any{"read": read}
		if level != "" {
			doc["encryption"] = map[string]any{"level": level}
		}
		return doc
	}
	want := map[string]string{"pub": "public", "priv": "private", "rest-pub": "public", "rest-priv": "private",
		"sealed-pub": "sealed", "sealed-priv": "sealed", "e": "e2e", "pub-draft": "private", "priv-open": "public"}
	mkNS(t, e, "pub", enc("public", ""))
	mkNS(t, e, "priv", enc("grant", ""))
	mkNS(t, e, "rest-pub", enc("public", "at-rest"))
	mkNS(t, e, "rest-priv", enc("grant", "at-rest"))
	mkNS(t, e, "sealed-pub", enc("public", "sealed"))
	mkNS(t, e, "sealed-priv", enc("grant", "sealed"))
	mkNS(t, e, "e", enc("grant", "e2e"))
	branch := func(base, name, read string) bool {
		r := who
		r.NS = base
		_, err := e.CreateBranch(ctx, r, BranchRequest{Name: name, IfNoneMatch: true,
			Patches: []any{map[string]any{"op": "replace", "path": "/read", "value": read}}})
		return err == nil
	}
	if !branch("pub", "pub-draft", "grant") {
		t.Fatal("a private branch of a public base wasn't created")
	}
	if !branch("priv", "priv-open", "public") {
		// §7.4 doesn't let a branch read wider than its base here.
		delete(want, "priv-open")
	}
	if err := e.read(ctx, func(t2 *tx) error {
		for ns, w := range want {
			if got := t2.archiveAccess(t2.nsByName(ns)); got != w {
				t.Errorf("archiveAccess(%s) = %q, want %q", ns, got, w)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
