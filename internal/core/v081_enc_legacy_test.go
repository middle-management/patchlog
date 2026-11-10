package core

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
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
	// This version counts its sealings (seal_counts, migration 016): the
	// table, for the writes building the fixture, until close15.
	if err := e.update(context.Background(), func(t *tx) error {
		_, err := t.Exec(`CREATE TABLE seal_counts (ns bigint NOT NULL, epoch bigint NOT NULL, name text NOT NULL, sealed bigint NOT NULL DEFAULT 0, reserved bigint NOT NULL DEFAULT 0, PRIMARY KEY (ns, epoch, name))`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

// close15 closes an engine open15 opened, leaving the schema as v0.26.1
// left it.
func (l *v081Legacy) close15(t *testing.T, e *Engine) {
	t.Helper()
	if err := e.update(context.Background(), func(t *tx) error {
		_, err := t.Exec(`DROP TABLE seal_counts`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.Close()
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
	l.close15(t, e)

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
	l.close15(t, e)
	e, err := Open(l.opts())
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	if raises, pending := l.tables(t); raises || pending {
		t.Fatalf("e2e_raises %v, remote_pending_sealings %v; want neither", raises, pending)
	}
}

// KEYS-9 (§E.2.1; stored.md item 9): migration 016 and the first Open
// after it seed seal_counts from what v0.26.1 stored: a stored document
// and entry of a revision with an epoch (rev_epochs) count under that
// epoch, a stored sealing without one under the epoch its kid names, a
// sealed blob under its epoch, and a revision whose epoch is fixed with
// no stored sealing reserves two.
func TestV081SealCountsSeeded(t *testing.T) {
	t.Parallel()
	l := newV081Legacy(t)
	e := l.open15(t)
	mkNS(t, e, "s", map[string]any{})
	for _, name := range []string{"a", "b", "c"} {
		if _, err := put(e, "s", name, "", 1); err != nil {
			t.Fatal(err)
		}
	}
	jwe := func(kid string) string {
		h := `{"alg":"dir","enc":"A256GCM","kid":"` + kid + `","pl":{}}`
		return base64.RawURLEncoding.EncodeToString([]byte(h)) + "..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA"
	}
	if err := e.update(context.Background(), func(t *tx) error {
		n := t.nsByName("s")
		seqOf := func(name string) int64 {
			r := t.resource(n.id, name)
			return r.headSeq.Int64
		}
		for _, q := range []struct {
			sql  string
			args []any
		}{
			// a: epoch 2 by rev_epochs, its document and entry stored.
			{`INSERT INTO rev_epochs (seq, epoch) VALUES (?, 2)`, []any{seqOf("a")}},
			{`INSERT INTO sealed (ns, kind, key, name, rev_seq, jwe, created) VALUES (?, 'doc', 'a/1', 'a', ?, ?, 0)`, []any{n.id, seqOf("a"), jwe("s#2")}},
			{`INSERT INTO sealed (ns, kind, key, name, rev_seq, jwe, created) VALUES (?, 'entry', 'a/1', 'a', ?, ?, 0)`, []any{n.id, seqOf("a"), jwe("s#2")}},
			// b: no rev_epochs row, its document stored under s#3.
			{`INSERT INTO sealed (ns, kind, key, name, rev_seq, jwe, created) VALUES (?, 'doc', 'b/1', 'b', ?, ?, 0)`, []any{n.id, seqOf("b"), jwe("s#3")}},
			// c: epoch 2 fixed, nothing stored: two reserved.
			{`INSERT INTO rev_epochs (seq, epoch) VALUES (?, 2)`, []any{seqOf("c")}},
			// A sealed blob of a under epoch 2.
			{`INSERT INTO blob_epochs (ns, name, bid, epoch, data, created) VALUES (?, 'a', ?, 2, ?, 0)`, []any{n.id, []byte("12345678901234567890"), []byte("x")}},
		} {
			_, err := t.Exec(q.sql, q.args...)
			t.must(err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	l.close15(t, e)
	e, err := Open(l.opts())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	got := map[string][2]int64{}
	if err := e.read(context.Background(), func(t *tx) error {
		rows, err := t.Query(`SELECT c.epoch, c.name, c.sealed, c.reserved FROM seal_counts c JOIN namespaces n ON n.ns = c.ns WHERE n.name = 's'`)
		t.must(err)
		defer rows.Close()
		for rows.Next() {
			var ep int
			var name string
			var s, r int64
			t.must(rows.Scan(&ep, &name, &s, &r))
			got[fmt.Sprintf("%d/%s", ep, name)] = [2]int64{s, r}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := map[string][2]int64{"2/a": {3, 0}, "3/b": {1, 0}, "2/c": {0, 2}}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: sealed, reserved %v, want %v (all %v)", k, got[k], v, got)
		}
	}
}
