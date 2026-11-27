package core

import (
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// A stale namespace row in the check's cache (spnscache.go) never decides
// a write: one that lets a write through that the namespace refuses now is
// caught by the re-check, and one that refuses a write the namespace
// allows now is read again.
func TestPGSpannerNSCacheStale(t *testing.T) {
	if !pgtest.Spanner() {
		t.Skip("Spanner only")
	}
	e := openInstance(t, pgtest.NewDB(t), t.TempDir())
	// Every write checks outside the lock, in a read transaction, as
	// under load: a write on its own checks inside it, uncached.
	e.noSolo = true
	cfg := mkNS(t, e, "n", map[string]any{"read": "public"})
	// The tailer sees the configuration write (meta) and flushes the
	// cache: after that, the check of a write keeps its row.
	time.Sleep(10 * tailEvery)
	if _, err := write(e, "n", "a", "", 1); err != nil {
		t.Fatal(err)
	}
	open, ok := e.nsc.get("n", time.Now())
	if !ok {
		t.Fatal("the check's namespace row isn't cached")
	}

	// Cached as purged, though it isn't: the check that read it refuses
	// (410), and runs again without the cache, which lets the write
	// through.
	purged := open
	purged.purged = true
	e.nsc.put(&purged, e.nsc.generation(), time.Now())
	if _, err := write(e, "n", "b", "", 2); err != nil {
		t.Fatalf("write refused by a stale cached row: %v", err)
	}
	if got, ok := e.nsc.get("n", time.Now()); !ok || got.purged {
		t.Fatalf("cached %+v, %v after the check read the row again", got, ok)
	}

	// Frozen, and cached as before: the re-check refuses the write.
	r := who
	r.NS = "n"
	if _, err := e.WriteConfig(context.Background(), r, ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.nsc.get("n", time.Now()); ok {
		t.Fatal("a configuration write left the namespace cached")
	}
	e.nsc.put(&open, e.nsc.generation(), time.Now())
	if _, err := write(e, "n", "c", "", 3); status(err) != 409 {
		t.Fatalf("write to a frozen namespace: %v, want 409", err)
	}
}
