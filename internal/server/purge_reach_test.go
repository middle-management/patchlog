package server

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// §8.3: a purge finds the branches it has something to do in by name
// rather than by visiting every branch (core, purgePlan), so every shape of
// branch it may meet is here, in one tree, with what it must do in each: a
// purge entry targeting the head the branch saw wherever it saw one, its
// own copy purged wherever it held one, and nothing where it saw none.
func TestPurgeReach(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("p", map[string]any{"read": "public"})
	e.create("p", "other", map[string]any{})
	before := e.nsHead("p")
	branch := func(base, name string) {
		t.Helper()
		expect(t, e.branch(base, map[string]any{"name": name}, "alice"), 201)
	}
	// Made before x existed: they never see p's x.
	branch("p", "old")
	branch("old", "old-kid")
	branch("old", "old-own")
	branch("old-own", "old-own-kid") // before old-own's x too
	x1 := e.create("p", "x", map[string]any{"v": 1.0})
	x2 := e.appendRev("p", "x", x1, ops(op("replace", "/v", 2.0)))
	// A document of the same name below a branch that sees none, and a
	// branch reading that one through.
	own := e.create("old-own", "x", map[string]any{"mine": true})
	// And one three branches down that see nothing.
	branch("old-kid", "old-kid2")
	branch("old-kid2", "deep-own")
	deep := e.create("deep-own", "x", map[string]any{"deep": true})
	branch("old-own", "old-own-late")
	// Made now, at a position before x existed.
	expect(t, e.branch("p", map[string]any{"name": "early", "at": before}, "alice"), 201)
	// Reading x through, at one level and two.
	branch("p", "rt")
	branch("rt", "rt-kid")
	// Its own chain on top of the one read through, with a branch from
	// before it and one from after.
	branch("p", "top")
	branch("top", "top-kid")
	t1 := e.appendRev("top", "x", x2, ops(op("replace", "/v", 3.0)))
	branch("top", "top-late")
	// Tombstoned in the branch.
	branch("p", "dead")
	tomb := e.del("dead", "x", x2)
	// Purged in the branch already, with a branch from before that purge
	// and one from after.
	branch("p", "gone")
	branch("gone", "gone-kid")
	expect(t, e.purge("gone", "x", x2, "admin"), 204)
	branch("gone", "gone-late")
	// Frozen, reading through and with its own chain.
	branch("p", "ice")
	branch("p", "ice-own")
	i1 := e.appendRev("ice-own", "x", x2, ops(op("replace", "/v", 4.0)))
	for _, ns := range []string{"ice", "ice-own"} {
		expect(t, e.patchNS(ns, ops(op("add", "/frozen", true)), ""), 201)
	}
	x3 := e.appendRev("p", "x", x2, ops(op("replace", "/v", 5.0)))

	// Each branch, the target of the purge entry it must get ("" for
	// none), and what its x answers afterwards.
	cases := []struct {
		ns, target string
		code       int
	}{
		{"old", "", 404}, {"old-kid", "", 404}, {"early", "", 404}, {"old-own-kid", "", 404},
		{"old-own", own, 410}, {"old-own-late", own, 410},
		{"old-kid2", "", 404}, {"deep-own", deep, 410},
		{"rt", x2, 410}, {"rt-kid", x2, 410},
		{"top", t1, 410}, {"top-kid", x2, 410}, {"top-late", t1, 410},
		{"dead", tomb, 410},
		{"gone", "", 410}, {"gone-kid", "", 410}, {"gone-late", "", 410},
		{"ice", x2, 410}, {"ice-own", i1, 410},
	}
	logs := map[string]int{}
	for _, c := range cases {
		logs[c.ns] = len(e.nsKinds(c.ns))
	}
	expect(t, e.purge("p", "x", x3, "admin"), 204)
	if en := e.lastNSEntry("p"); en["kind"] != "purge" || en["target"] != x3 {
		t.Fatalf("p's last entry %v", en)
	}
	for _, c := range cases {
		n, en := len(e.nsKinds(c.ns)), e.lastNSEntry(c.ns)
		switch {
		case c.target == "" && n != logs[c.ns]:
			t.Errorf("%s got an entry: %v", c.ns, en)
		case c.target != "" && (n != logs[c.ns]+1 || en["kind"] != "purge" || en["resource"] != "x" || en["target"] != c.target):
			t.Errorf("%s: %d entries after %d, the last %v; want one more, a purge of x targeting %s", c.ns, n, logs[c.ns], en, c.target)
		}
		if g := e.get("/r/" + c.ns + "/x"); g.Code != c.code {
			t.Errorf("/r/%s/x after the purge: %d, want %d", c.ns, g.Code, c.code)
		}
	}
	// The own copies' revisions are gone, not only their heads.
	for ns, rev := range map[string]string{"old-own": own, "top": t1, "ice-own": i1, "dead": x2} {
		if g := e.get("/r/" + ns + "/x/rev/" + rev); g.Code != 410 {
			t.Errorf("/r/%s/x/rev/%s after the purge: %d", ns, rev, g.Code)
		}
	}
	// Another name is untouched everywhere, and a branch that saw no x may
	// still create its own.
	expect(t, e.get("/r/rt/other"), 302)
	e.create("old", "x", map[string]any{"new": true})
	expect(t, e.get("/r/old-kid/x"), 404)
}

// §8.3, §E.2.2: the sealed copies a branch stored of a document it read
// through go with the purge in its base, and so do its own; a branch made
// before the document existed is skipped.
func TestPurgeReachSealedCopies(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sealed.db")
	if pgtest.Enabled() {
		path = pgtest.NewDB(t)
	}
	e := newSealedEnv(t, withPath(path))
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	expect(t, e.branch("s", map[string]any{"name": "pre"}, "admin"), 201)
	a := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	keep := e.wr("s", "keep", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	expect(t, e.branch("s", map[string]any{"name": "b"}, "admin"), 201)
	expect(t, e.branch("b", map[string]any{"name": "bb"}, "admin"), 201)
	expect(t, e.branch("s", map[string]any{"name": "o"}, "admin"), 201)
	o := e.wr("o", "a", a, withNonce(ops(op("replace", "/v", 2.0))))
	// Reading stores the copies sealed for each namespace.
	for _, p := range []string{"/r/s/a/rev/" + a, "/r/b/a/rev/" + a, "/r/bb/a/rev/" + a, "/r/o/a/rev/" + o, "/r/o/a/rev/" + a, "/r/b/keep/rev/" + keep} {
		expect(t, e.get(p), 200)
	}
	stored := func(name string) map[string]int {
		t.Helper()
		driver, dsn := "sqlite", sqlitedsn.DSN(path, "_pragma=busy_timeout(10000)")
		if strings.HasPrefix(path, "postgres") {
			driver, dsn = "pgx", pgtest.DSN(path)
		}
		db, err := sql.Open(driver, dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		rows, err := db.Query(`SELECT n.name, COUNT(*) FROM sealed s JOIN namespaces n ON n.ns = s.ns WHERE s.name = '` + name + `' GROUP BY n.name`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]int{}
		for rows.Next() {
			var ns string
			var k int
			if err := rows.Scan(&ns, &k); err != nil {
				t.Fatal(err)
			}
			out[ns] = k
		}
		return out
	}
	if got := stored("a"); got["s"] == 0 || got["b"] == 0 || got["bb"] == 0 || got["o"] == 0 {
		t.Fatalf("sealed copies of a before the purge: %v", got)
	}
	pre := e.nsHead("pre")
	heads := map[string]string{}
	for _, ns := range []string{"s", "b", "bb", "o"} {
		heads[ns] = e.nsHead(ns)
	}
	expect(t, e.purge("s", "a", a, "admin"), 204)
	if got := stored("a"); len(got) != 0 {
		t.Fatalf("sealed copies of a after the purge: %v", got)
	}
	if got := stored("keep"); got["b"] == 0 {
		t.Fatalf("sealed copies of another document after the purge: %v", got)
	}
	for _, ns := range []string{"s", "b", "bb", "o"} {
		// The logs are sealed: an entry moved the head.
		if e.nsHead(ns) == heads[ns] {
			t.Errorf("%s got no entry", ns)
		}
		expect(t, e.get("/r/"+ns+"/a/rev/"+a), 410)
	}
	if e.nsHead("pre") != pre {
		t.Fatalf("pre, made before a, got an entry: %v", e.lastNSEntry("pre"))
	}
}
