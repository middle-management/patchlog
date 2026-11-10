package core

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// migrationsUpTo is the embedded migrations up to version n, without
// current.sql: the schema a release that stopped there left.
func migrationsUpTo(t *testing.T, n int) fs.FS {
	t.Helper()
	out := fstest.MapFS{}
	for _, dir := range []string{"migrations/sqlite", "migrations/postgres", "migrations/seed"} {
		ents, err := fs.ReadDir(migrations, dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			name := e.Name()
			if dir != "migrations/seed" {
				v, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
				if err != nil || v > n {
					continue
				}
			}
			b, err := fs.ReadFile(migrations, dir+"/"+name)
			if err != nil {
				t.Fatal(err)
			}
			out[dir+"/"+name] = &fstest.MapFile{Data: b}
		}
	}
	return out
}

// v081Legacy is a database a v0.26.1 deployment left (migrations up to
// 015), at path, opened with the options opts gives.
type v081Legacy struct {
	path string
	opts func() Options
}

func newV081Legacy(t *testing.T) *v081Legacy {
	t.Helper()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	path := pgtest.FreshDB(t)
	if !pgtest.Enabled() {
		path = filepath.Join(t.TempDir(), "legacy.db")
	}
	blobs := t.TempDir()
	return &v081Legacy{path: path, opts: func() Options {
		return Options{Path: path, BlobDir: blobs, AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
			Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}, KeyStore: ks}
	}}
}

// open15 opens it at its old schema, with raises to e2e let through and
// recorded as v0.26.1 recorded them.
func (l *v081Legacy) open15(t *testing.T) *Engine {
	t.Helper()
	o := l.opts()
	o.migrations = migrationsUpTo(t, 15)
	o.LegacyE2ERaiseForTests = true
	e, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// raise raises ns to sealed, which gives it an epoch key, and then to e2e,
// and records that in e2e_raises, as v0.26.1 did.
func (l *v081Legacy) raise(t *testing.T, e *Engine, ns string) {
	t.Helper()
	ctx := context.Background()
	for _, enc := range []map[string]any{{"level": "sealed"}, {"level": "e2e", "epoch": 2.0}} {
		h, err := e.NamespaceHead(ctx, ns, Credentials{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.WriteConfig(ctx, p29Req(ns), ConfigChange{IfMatch: h.Config, Patches: []any{map[string]any{"op": "add", "path": "/encryption", "value": enc}}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.update(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		_, err := t.Exec(`INSERT INTO e2e_raises (ns, config_seq, level, epoch, pad, created) VALUES (?,?,2,1,0,0)`, n.id, n.configSeq)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n := v081Count(t, e, `SELECT COUNT(*) FROM epoch_keys WHERE ns IN (SELECT ns FROM namespaces WHERE name = ?)`, ns); n == 0 {
		t.Fatalf("%s has no epoch key", ns)
	}
}

// v081Count counts with the engine's database.
func v081Count(t *testing.T, e *Engine, q string, args ...any) int {
	t.Helper()
	var n int
	if err := e.read(context.Background(), func(t *tx) error {
		t.must(t.QueryRow(q, args...).Scan(&n))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// tables reports whether e2e_raises and remote_pending_sealings exist in
// the database at l.path.
func (l *v081Legacy) tables(t *testing.T) (raises, pending bool) {
	t.Helper()
	driver, dsn, pg := "sqlite", sqlitedsn.DSN(l.path, "_pragma=busy_timeout(10000)"), false
	if pgtest.Enabled() {
		driver, dsn, pg = "pgx", pgtest.DSN(l.path), true
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raises, err = tableExists(db, pg, "e2e_raises")
	if err != nil {
		t.Fatal(err)
	}
	pending, err = tableExists(db, pg, "remote_pending_sealings")
	if err != nil {
		t.Fatal(err)
	}
	return raises, pending
}

// E2E-2 (Addendum E Levels Invariant, v0.78; stored.md item 1): a
// database holding a namespace a pre-v0.78 deployment raised to e2e is
// refused at Open, before it is migrated, naming it, and with the remedy;
// both marker tables stay. With PurgeRaisedE2E it opens: the namespace and
// its local branch are purged, their epoch keys destroyed, and they answer
// 410 purged; migration 016 dropped the marker tables.
func TestV081OpenRefusesRaisedE2E(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := newV081Legacy(t)
	e := l.open15(t)
	mkNS(t, e, "m", map[string]any{})
	if _, err := e.WriteResource(ctx, p29Req("m"), Item{Resource: "x", IfNoneMatch: true, Steps: []Step{{Patches: []any{p29Add("", map[string]any{"v": 1.0})}}}}); err != nil {
		t.Fatal(err)
	}
	mkNS(t, e, "plain", map[string]any{})
	l.raise(t, e, "m")
	if _, err := e.CreateBranch(ctx, p29Req("m"), BranchRequest{Name: "mb", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	e.Close()

	_, err := Open(l.opts())
	if err == nil || !strings.Contains(err.Error(), "namespace m") || !strings.Contains(err.Error(), "§G.5.1") || !strings.Contains(err.Error(), "purge-raised-e2e") {
		t.Fatalf("Open of a database with a namespace raised to e2e: %v", err)
	}
	if raises, pending := l.tables(t); !raises || !pending {
		t.Fatalf("after the refusal: e2e_raises %v, remote_pending_sealings %v; want both kept", raises, pending)
	}

	o := l.opts()
	o.PurgeRaisedE2E = true
	e, err = Open(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"m", "mb"} {
		var ae *Error
		if _, err := e.ResourceHead(ctx, ns, "x", Credentials{Author: "a"}); !errors.As(err, &ae) || ae.Status != 410 {
			t.Fatalf("%s after -purge-raised-e2e: %v, want 410", ns, err)
		}
	}
	if n := v081Count(t, e, `SELECT COUNT(*) FROM epoch_keys WHERE ns IN (SELECT ns FROM namespaces WHERE name = 'm')`); n != 0 {
		t.Fatalf("m's epoch keys: %d rows left", n)
	}
	if n := v081Count(t, e, `SELECT COUNT(*) FROM namespaces WHERE name = 'plain' AND purged = 0`); n != 1 {
		t.Fatal("a namespace that wasn't raised was purged")
	}
	e.Close()
	if raises, pending := l.tables(t); raises || pending {
		t.Fatalf("after migrating: e2e_raises %v, remote_pending_sealings %v; want neither", raises, pending)
	}
	// It opens without the flag from now on.
	e, err = Open(l.opts())
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
}

// E2E-11: migrating a database whose only raised namespace was purged
// under v0.26.1 needs no flag, and leaves neither marker table.
func TestV081MigrationDropsMarkersOfPurged(t *testing.T) {
	t.Parallel()
	l := newV081Legacy(t)
	e := l.open15(t)
	mkNS(t, e, "m", map[string]any{})
	l.raise(t, e, "m")
	if err := e.update(context.Background(), func(t *tx) error {
		_, err := t.Exec(`UPDATE namespaces SET purged = 1 WHERE name = 'm'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.Close()
	e, err := Open(l.opts())
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	if raises, pending := l.tables(t); raises || pending {
		t.Fatalf("e2e_raises %v, remote_pending_sealings %v; want neither", raises, pending)
	}
}
