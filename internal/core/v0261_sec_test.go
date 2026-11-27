package core

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/dbmigrate"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// Security review of v0.26.0, as v0.91 answers it: a covered purged
// namespace's filtered /heads (FilteredCurrent, FilteredHeads) answers
// 410 purged to every request, whatever the grant or cookie and whatever
// the live namespace would answer, before any read check: a purge, unlike
// existence, is no secret, and no key is left to verify a grant with
// (§8.5, §7.9 Purged namespaces, §E.4). Until v0.91 a reader owed 401/403
// got that answer, never the 410.
func TestV0261FilteredPurgedHeadsDifferential(t *testing.T) {
	ctx := context.Background()
	type world struct {
		w       *v75World
		vid, at string
		bo      string // another partial reader's vid
		creds   map[string]Credentials
	}
	mk := func(purge bool) *world {
		w := newV75World(t, v75Opts{})
		w.seed()
		li := w.li()
		bo := w.bo()
		x := &world{w: w}
		x.vid = v075ViewID(t, w, li)
		x.bo = v075ViewID(t, w, bo)
		red, st := v76fRedirect(t, w, "matches", x.vid, li)
		if red == nil {
			t.Fatalf("redirect: %d", st)
		}
		x.at = red.At
		x.creds = map[string]Credentials{
			"none":         {},
			"garbage":      {Bearer: "not-a-grant"},
			"other-ns":     w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:x", "ns": []any{"cat-season"}, "can": []any{"read"}}),
			"no-read":      w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:x", "ns": []any{"matches"}, "can": []any{"create"}}),
			"li-wrong-vid": li,
			"bo":           bo,
		}
		if purge {
			v077Purge(t, w, "matches")
		}
		return x
	}
	live, purged := mk(false), mk(true)
	type call func(x *world, c Credentials, vid, at string) error
	calls := map[string]call{
		"current": func(x *world, c Credentials, vid, _ string) error {
			return x.w.e.FilteredCurrent(ctx, "matches", vid, "/heads", c)
		},
		"at": func(x *world, c Credentials, vid, at string) error {
			_, _, err := x.w.e.FilteredHeads(ctx, "matches", vid, at, "", "", c)
			return err
		},
		"bogus-at": func(x *world, c Credentials, vid, _ string) error {
			_, _, err := x.w.e.FilteredHeads(ctx, "matches", vid, "zzzz", "", "", c)
			return err
		},
	}
	for cn, call := range calls {
		for who := range live.creds {
			for _, viewKind := range []string{"li", "bo"} {
				if who == "bo" && viewKind == "bo" || who == "li-wrong-vid" && viewKind == "li" {
					continue // the reader's own vid: admitted, 410 is owed
				}
				g := func(x *world) string {
					if viewKind == "bo" {
						return x.bo
					}
					return x.vid
				}
				el := call(live, live.creds[who], g(live), live.at)
				ep := call(purged, purged.creds[who], g(purged), purged.at)
				sl, sp := v75Status(el), v75Status(ep)
				t.Logf("%-8s %-11s vid=%s: live %d, purged %d", cn, who, viewKind, sl, sp)
				if sp != 410 || v75Code(ep) != "purged" {
					t.Errorf("%s %s with %s's vid: purged answers %d (%v), want 410 purged; the live namespace %d (%v)", cn, who, viewKind, sp, ep, sl, el)
				}
			}
		}
	}
}

// v0.26.1 review: migration 015's DELETE, run over seeded rows: it
// deletes the rows of a purged resource and of a purged shadow namespace,
// and keeps those of a live resource and of a tombstoned one. Since v0.81
// a database at migration 014 is seeded directly, and 015 runs on it as
// an upgrade from v0.26.0 would run it (the table goes in 016).
func TestV0261Migration015Delete(t *testing.T) {
	t.Parallel()
	l := newV081Legacy(t)
	o := l.opts()
	o.migrations = migrationsUpTo(t, 14)
	e, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"s", "q"} {
		mkNS(t, e, ns, map[string]any{})
		for _, name := range []string{"live", "tomb", "gone"} {
			if _, err := put(e, ns, name, "", 1); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := e.update(context.Background(), func(t *tx) error {
		for _, ns := range []string{"s", "q"} {
			n := t.nsByName(ns)
			for _, name := range []string{"live", "tomb", "gone"} {
				_, err := t.Exec(`INSERT INTO remote_pending_sealings (shadow, name, kind, ref, epoch, rev_seq, kid, pl, want, answer, horizon, updated)
					VALUES (?,?,'doc','r',1,1,?,'{}',?,'refused',NULL,0)`, n.id, name, ns+"#1", []byte("w"))
				t.must(err)
			}
			_, err := t.Exec(`UPDATE resources SET state = 1 WHERE ns = ? AND name = 'tomb'`, n.id)
			t.must(err)
			_, err = t.Exec(`UPDATE resources SET state = 2 WHERE ns = ? AND name = 'gone'`, n.id)
			t.must(err)
		}
		_, err := t.Exec(`UPDATE namespaces SET purged = 1 WHERE name = 'q'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.Close()
	// Migration 015 as an upgrade from v0.26.0 runs it, on the database
	// itself: an engine of this version refuses to open with those rows
	// (legacy_e2e.go).
	driver, dsn := "sqlite", sqlitedsn.DSN(l.path, "_pragma=busy_timeout(10000)")
	if pgtest.Enabled() {
		driver, dsn = "pgx", pgtest.DSN(l.path)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := dbmigrate.Migrate(context.Background(), db, migrationsUpTo(t, 15), "patchlog"); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(`SELECT n.name, p.name FROM remote_pending_sealings p JOIN namespaces n ON n.ns = p.shadow ORDER BY 1, 2`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var a, b string
		if err := rows.Scan(&a, &b); err != nil {
			t.Fatal(err)
		}
		got = append(got, a+"/"+b)
	}
	if strings.Join(got, ",") != "s/live,s/tomb" {
		t.Fatalf("rows left: %s", strings.Join(got, ","))
	}
}
