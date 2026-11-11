package core

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// v82encRows counts with the database at l.path, no engine open.
func v82encRows(t *testing.T, l *v081Legacy, q string) int {
	t.Helper()
	driver, dsn := "sqlite", sqlitedsn.DSN(l.path, "_pragma=busy_timeout(10000)")
	if pgtest.Enabled() {
		driver, dsn = "pgx", pgtest.DSN(l.path)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(q).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// E2E-13 (Reading this spec; CONFORMANCE CONF-6, scenario 77), with
// E2E-5's cleanup: the start gate comes first. A database holding a
// namespace an earlier draft raised to e2e is refused before anything of
// it changes: no migration runs and cleanStaleSnapshots deletes nothing,
// so a refused start leaves the database as its own version left it.
// With PurgeRaisedE2E the raised namespace is purged, never served, and
// only then are the snapshots behind a moved horizon deleted.
func TestV082GateBeforeSnapshotCleanup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := newV081Legacy(t)
	e := l.open15(t)
	mkNS(t, e, "m", map[string]any{})
	mkNS(t, e, "other", map[string]any{})
	for _, ns := range []string{"m", "other"} {
		w, err := e.WriteResource(ctx, p29Req(ns), Item{Resource: "x", IfNoneMatch: true, Steps: []Step{{Patches: []any{p29Add("", map[string]any{"v": 1.0})}}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.WriteResource(ctx, p29Req(ns), Item{Resource: "x", IfMatch: w.Items[0].IDs[0], Steps: []Step{{Patches: []any{p29Add("/v", 2.0)}}}}); err != nil {
			t.Fatal(err)
		}
	}
	l.raise(t, e, "m")
	// Two snapshot rows for other's x, which has no horizon: what a
	// restore and a second prune of an earlier version could leave, and
	// what cleanStaleSnapshots deletes.
	if err := e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`INSERT INTO e2e_snapshots (seq, res, jwe) SELECT v.seq, v.res, 'stale' FROM revisions v JOIN resources r ON r.res = v.res JOIN namespaces n ON n.ns = r.ns WHERE n.name = 'other'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	l.close15(t, e)
	const stale = `SELECT COUNT(*) FROM e2e_snapshots`
	if n := v82encRows(t, l, stale); n != 2 {
		t.Fatalf("the fixture holds %d snapshot rows, want 2", n)
	}

	// Refused, twice: nothing migrated, nothing cleaned.
	for range 2 {
		_, err := Open(l.opts())
		if err == nil || !strings.Contains(err.Error(), "namespace m") || !strings.Contains(err.Error(), "purge-raised-e2e") {
			t.Fatalf("Open of a database with a namespace raised to e2e: %v", err)
		}
		if raises, pending := l.tables(t); !raises || !pending {
			t.Fatalf("the refused start migrated: e2e_raises %v, remote_pending_sealings %v", raises, pending)
		}
		if n := v82encRows(t, l, stale); n != 2 {
			t.Fatalf("the refused start deleted snapshots: %d rows left of 2", n)
		}
	}

	// With the flag: m is purged, then the stale rows go.
	o := l.opts()
	o.PurgeRaisedE2E = true
	e, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var ae *Error
	if _, err := e.ResourceHead(ctx, "m", "x", Credentials{Author: "a"}); !errors.As(err, &ae) || ae.Status != 410 {
		t.Fatalf("m after -purge-raised-e2e: %v, want 410", err)
	}
	if n := v081Count(t, e, stale); n != 0 {
		t.Fatalf("%d stale snapshot rows after the start", n)
	}
	if h, err := e.ResourceHead(ctx, "other", "x", Credentials{Author: "a"}); err != nil || h.State != Live {
		t.Fatalf("a namespace that wasn't raised: %+v %v", h, err)
	}
}
