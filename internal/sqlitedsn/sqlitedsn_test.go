package sqlitedsn_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

const pragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)"

func TestDSN(t *testing.T) {
	for _, c := range []struct{ path, query, want string }{
		{"/var/lib/patchlog.db", pragmas, "file:///var/lib/patchlog.db?" + pragmas},
		{"patchlog.db", pragmas, "file:patchlog.db?" + pragmas},
		{"data/patchlog.db", "", "file:data/patchlog.db"},
		{":memory:", "_txlock=immediate", "file::memory:?_txlock=immediate"},
		// t.TempDir of an unnamed subtest.
		{"/tmp/TestOpen_#00123/001/test.db", pragmas, "file:///tmp/TestOpen_%2300123/001/test.db?" + pragmas},
		{"/srv/what?.db", pragmas, "file:///srv/what%3F.db?" + pragmas},
		{"/srv/100%.db", pragmas, "file:///srv/100%25.db?" + pragmas},
		{"/srv/a%41b.db", "", "file:///srv/a%2541b.db"},
		{"/srv/#?%/x.db", "", "file:///srv/%23%3F%25/x.db"},
		{"/Application Support/p l.db", pragmas, "file:///Application Support/p l.db?" + pragmas},
		{"/srv/smörgåsbord ✓.db", "", "file:///srv/smörgåsbord ✓.db"},
		{"/srv/a+b;c=d&e.db", "", "file:///srv/a+b;c=d&e.db"},
		{"//srv/x.db", "", "file:////srv/x.db"},
		{`C:\Users\me\patchlog.db`, "", `file:C:\Users\me\patchlog.db`},
	} {
		if got := sqlitedsn.DSN(c.path, c.query); got != c.want {
			t.Errorf("DSN(%q, %q) = %q, want %q", c.path, c.query, got, c.want)
		}
	}
}

// Each DSN opens the database at exactly its path, with the parameters
// applied, and no other file appears: before DSN, "file:" + path cut the
// path at '#' or '?' and decoded "%41" to "A".
func TestDSNOpensThatFile(t *testing.T) {
	dir := t.TempDir()
	names := []string{"plain.db", "a#00b.db", "a?b.db", "a%41b.db", "a%zz.db", "sp ace.db", "smörgåsbord ✓.db", "#?%.db", "d#1?x/i.db"}
	if err := os.Mkdir(filepath.Join(dir, "d#1?x"), 0o755); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, n := range names {
		paths = append(paths, filepath.Join(dir, n))
	}
	paths = append(paths, "//"+strings.TrimLeft(filepath.Join(dir, "slashes.db"), "/"))
	for i, path := range paths {
		open := func() *sql.DB {
			t.Helper()
			db, err := sql.Open("sqlite", sqlitedsn.DSN(path, pragmas))
			if err != nil {
				t.Fatal(err)
			}
			return db
		}
		db := open()
		if _, err := db.Exec(`CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (?)`, i); err != nil {
			t.Errorf("%q: %v", path, err)
			db.Close()
			continue
		}
		var jm string
		var bt int
		if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&jm); err != nil || jm != "wal" {
			t.Errorf("%q: journal_mode %q, %v", path, jm, err)
		}
		if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&bt); err != nil || bt != 10000 {
			t.Errorf("%q: busy_timeout %d, %v", path, bt, err)
		}
		db.Close()
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%q: %v", path, err)
		}
		db = open()
		var v int
		if err := db.QueryRow(`SELECT v FROM t`).Scan(&v); err != nil || v != i {
			t.Errorf("%q reopened: %d, %v", path, v, err)
		}
		db.Close()
	}
	var got []string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			got = append(got, strings.TrimPrefix(p, dir+string(filepath.Separator)))
		}
		return err
	})
	want := append([]string{"slashes.db"}, names...)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("files %q, want %q", got, want)
	}
}

// A relative path stays relative to the working directory.
func TestDSNRelative(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	db, err := sql.Open("sqlite", sqlitedsn.DSN("r#1?.db", pragmas))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE t (v INTEGER)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := os.Stat(filepath.Join(dir, "r#1?.db")); err != nil {
		t.Error(err)
	}
}

// Legacy names the file that the DSN of earlier releases, "file:" + path +
// "?" + the core's parameters, opened: each such DSN is opened here, in a
// directory of its own, and the one file that appears must be Legacy's,
// or path when Legacy is "" (or none, when that DSN fails).
func TestLegacy(t *testing.T) {
	const core = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(ON)&_txlock=immediate"
	base := t.TempDir()
	names := []string{"plain.db", "sp ace.db", "smörgåsbord ✓.db", "a+b;c=d&e.db",
		"a#00b.db", "a?b.db", "a#1?b.db", "a?b#1.db", "?b.db",
		"a%41b.db", "a%2541b.db", "%23x.db", "%3Fx.db", "s%2Fb.db", "s%2fb.db",
		"100%.db", "a%zz.db", "a%4", "a%00b.db", "a?b%zz.db", "a?b;c.db", "a#b%zz.db"}
	for i, name := range names {
		dir := filepath.Join(base, fmt.Sprint(i))
		if err := os.MkdirAll(filepath.Join(dir, "s"), 0o755); err != nil {
			t.Fatal(err)
		}
		checkLegacy(t, dir, filepath.Join(dir, name), core)
	}
	// The authority: empty or "localhost", or the open fails.
	dir := filepath.Join(base, "auth")
	os.Mkdir(dir, 0o755)
	checkLegacy(t, dir, "//localhost"+filepath.Join(dir, "lh.db"), core)
	checkLegacy(t, dir, "/"+filepath.Join(dir, "h.db"), core)
	checkLegacy(t, dir, "//"+filepath.Join(dir, "e.db"), core)
	for _, c := range []struct{ path, want string }{
		{"/srv/x.db#prod", "/srv/x.db"},
		{"/srv/x.db?prod", "/srv/x.db"},
		{"/srv/50%41.db", "/srv/50A.db"},
		{"/srv/a%2Fb.db", "/srv/a/b.db"},
		{"/srv/x.db", ""},
		{"/srv/100%.db", ""},
		{"/srv/a%00b.db", "/srv/a"},
		{":memory:", ""},
		{`C:\Users\me\patchlog.db`, ""},
	} {
		if got := sqlitedsn.Legacy(c.path); got != c.want {
			t.Errorf("Legacy(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func checkLegacy(t *testing.T, dir, path, query string) {
	t.Helper()
	want := sqlitedsn.Legacy(path)
	db, err := sql.Open("sqlite", "file:"+path+"?"+query)
	if err == nil {
		_, err = db.Exec(`CREATE TABLE t (v INTEGER)`)
		db.Close()
	}
	var got []string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && !strings.HasSuffix(p, "-wal") && !strings.HasSuffix(p, "-shm") {
			got = append(got, p)
		}
		return err
	})
	for _, p := range got {
		os.Remove(p)
	}
	switch {
	case err != nil && want != "":
		t.Errorf("%q: Legacy %q, but the old DSN failed: %v", path, want, err)
	case err != nil:
	case want == "" && (len(got) != 1 || !sameFile(got[0], path)):
		t.Errorf("%q: Legacy \"\", but the old DSN opened %q", path, got)
	case want != "" && (len(got) != 1 || got[0] != want):
		t.Errorf("%q: Legacy %q, but the old DSN opened %q", path, want, got)
	}
}

func sameFile(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

// CheckLegacy refuses only a path with no file whose Legacy file exists
// and is a regular file.
func TestCheckLegacy(t *testing.T) {
	dir := t.TempDir()
	touch := func(p string) {
		t.Helper()
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path, old := filepath.Join(dir, "x.db#prod"), filepath.Join(dir, "x.db")
	if err := sqlitedsn.CheckLegacy(path); err != nil {
		t.Errorf("neither file: %v", err)
	}
	touch(old)
	if err := sqlitedsn.CheckLegacy(path); err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), old) {
		t.Errorf("legacy file only: %v", err)
	}
	if err := sqlitedsn.CheckLegacy(old); err != nil {
		t.Errorf("a plain path: %v", err)
	}
	touch(path)
	if err := sqlitedsn.CheckLegacy(path); err != nil {
		t.Errorf("both files: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := sqlitedsn.CheckLegacy(filepath.Join(dir, "d?x.db")); err != nil {
		t.Errorf("legacy name a directory: %v", err)
	}
}
