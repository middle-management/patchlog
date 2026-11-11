package derived

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	_ "modernc.org/sqlite"

	"github.com/middle-management/patchlog/internal/dbmigrate"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// v82Entry is a body member given as a struct, as the services give
// some: its canonical form orders its members by name, not by field.
type v82Entry struct {
	Name  string `json:"name"`
	Href  string `json:"href"`
	Count int    `json:"count"`
}

// SVC-03 (SERVICES §E.2.6 What gets sealed; SPEC §3.1): each plaintext a
// view seals is canonical JSON (RFC 8785), before any padding: a whole
// response's is the response body, an entry's the object of the members
// it replaces. encoding/json's own form differs for each member here:
// U+2028 is escaped, keys are ordered by UTF-8 instead of UTF-16 code
// units, 1e21 is written in full, and struct fields keep their order.
func TestV082SealedPlaintextCanonical(t *testing.T) {
	ke := seal.NewKey()
	v := View{NS: "n", Target: "/n/at/1abc/children"}
	body := map[string]any{
		"sep":         "a\u2028b",
		"\U0001F600":  "astral key",
		"\uE000":      "private-use key",
		"big":         1e21,
		"size":        int64(1234),
		"entries":     []v82Entry{{Name: "b", Href: "/r/n/b", Count: 2}},
		"<html>&":     "kept as is",
		"children":    []any{map[string]any{"z": 1, "a": []string{"x"}}},
		"nothing":     nil,
		"placeholder": true,
	}
	// What a reader that parses the plaintext and serialises it again
	// canonically gets: the same bytes.
	want := `{"<html>&":"kept as is","big":1e+21,"children":[{"a":["x"],"z":1}],"entries":[{"count":2,"href":"/r/n/b","name":"b"}],` +
		`"nothing":null,"placeholder":true,"sep":"a` + "\u2028" + `b","size":1234,"` + "\U0001F600" + `":"astral key","` + "\uE000" + `":"private-use key"}`
	keyOf := func(kid string) []byte {
		if kid == "n#2" {
			return ke
		}
		return nil
	}
	for _, pad := range []bool{false, true} {
		k := Key{NS: "n", Epoch: 2, K: ke, Pad: pad}
		whole, err := SealView(k, v, body)
		if err != nil {
			t.Fatal(err)
		}
		item, err := SealItem(k, v, "r", body)
		if err != nil {
			t.Fatal(err)
		}
		wpt, err := OpenView(whole, keyOf, v)
		if err != nil {
			t.Fatal(err)
		}
		ipt, err := OpenItem(item, ItemKey(keyOf, "n", "r"), v, "n", "r")
		if err != nil {
			t.Fatal(err)
		}
		for what, pt := range map[string][]byte{"a whole response": wpt, "an entry": ipt} {
			if pad {
				// Padding comes after: spaces up to the size bucket.
				if len(pt) != seal.PadLen(len(want)) {
					t.Errorf("%s, padded: %d bytes, want the bucket of %d", what, len(pt), len(want))
				}
				pt = bytes.TrimRight(pt, " ")
			}
			if string(pt) != want {
				t.Errorf("%s (pad %v):\n got %s\nwant %s", what, pad, pt, want)
			}
			parsed, err := jsonv.Parse(pt)
			if err != nil || !bytes.Equal(jsonv.Canonical(parsed), pt) {
				t.Errorf("%s (pad %v): the plaintext isn't canonical(parsed): %v", what, pad, err)
			}
		}
	}
}

// SVC-01 (SERVICES §E.2.6 view, View keys): view is the request target
// in origin form, byte for byte as the service's redirect gave it. A
// reader that fetched another spelling of the same URL, or prefixes
// scheme and host, has another view: ErrMismatch, judged on pl before any
// key is derived.
func TestV082ViewIsTheTargetByteForByte(t *testing.T) {
	ke := seal.NewKey()
	k := Key{NS: "n", Epoch: 1, K: ke}
	const target = "/n/at/1abc/children?of=a%20b&sort=title"
	v := View{NS: "n", Target: target}
	whole, err := SealView(k, v, map[string]any{"children": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	item, err := SealItem(k, v, "r", map[string]any{"title": "T"})
	if err != nil {
		t.Fatal(err)
	}
	keyOf := func(string) []byte { return ke }
	if _, err := OpenView(whole, keyOf, v); err != nil {
		t.Fatalf("the target as served: %v", err)
	}
	for what, other := range map[string]string{
		"+ for a space":         "/n/at/1abc/children?of=a+b&sort=title",
		"an encoded slash":      "/n/at/1abc%2fchildren?of=a%20b&sort=title",
		"reordered parameters":  "/n/at/1abc/children?sort=title&of=a%20b",
		"scheme and host":       "https://tree.example" + target,
		"a trailing ?":          "/n/at/1abc/children?of=a%20b&sort=title&",
		"the path alone":        "/n/at/1abc/children",
		"a fragment":            target + "#x",
		"an unescaped space":    "/n/at/1abc/children?of=a b&sort=title",
		"a host without scheme": "//tree.example" + target,
	} {
		if other == target {
			continue
		}
		o := View{NS: "n", Target: other}
		if _, err := OpenView(whole, keyOf, o); !errors.Is(err, seal.ErrMismatch) {
			t.Errorf("a whole response opened as %s: %v, want ErrMismatch", what, err)
		}
		if _, err := OpenItem(item, ItemKey(keyOf, "n", "r"), o, "n", "r"); !errors.Is(err, seal.ErrMismatch) {
			t.Errorf("an entry opened as %s: %v, want ErrMismatch", what, err)
		}
	}
	// No view has min (§A.5): CanonicalQuery drops it from what is sealed.
	if q := CanonicalQuery(map[string][]string{"of": {"a"}, "min": {"n:1abc"}}, "min"); strings.Contains(q, "min") {
		t.Errorf("a view's query keeps min: %q", q)
	}
}

// SVC-05 (SERVICES §E.2.6 Per-entry sealing): until a service can judge
// the epoch of a revision it seals nothing derived from it. KeyAt gives
// no key for an epoch that isn't known, never the current one's: it
// refuses before it reads anything (k has no client here).
func TestV082KeyAtRefusesUnjudged(t *testing.T) {
	k := NewKeys(nil, nil)
	for _, e := range []int{0, -1, -2, -3} {
		key, err := k.KeyAt(context.Background(), "n", e)
		if !errors.Is(err, ErrUnjudged) {
			t.Errorf("KeyAt(%d): %v, want ErrUnjudged", e, err)
		}
		if key.K != nil || key.Epoch != 0 {
			t.Errorf("KeyAt(%d) gave a key: epoch %d", e, key.Epoch)
		}
	}
}

// SVC-03, SVC-05, SVC-07 (stored data): views a v0.27.0 service stored
// may hold plaintexts that aren't canonical, values sealed under an epoch
// never judged, or a preview's entries under its base's keys. Derived
// migration 003 deletes them; they are sealed again on demand, and a view
// stored since is kept across a restart.
func TestV082CacheDropsStoredViews(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", sqlitedsn.DSN(filepath.Join(t.TempDir(), "c.db"), ""))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// As v0.27.0 left it: migrations 001 and 002.
	old := fstest.MapFS{}
	ents, err := fs.ReadDir(migrations, "migrations/sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "001_") || strings.HasPrefix(e.Name(), "002_") {
			b, err := fs.ReadFile(migrations, "migrations/sqlite/"+e.Name())
			if err != nil {
				t.Fatal(err)
			}
			old["migrations/sqlite/"+e.Name()] = &fstest.MapFile{Data: b}
		}
	}
	if len(old) != 2 {
		t.Fatalf("migrations 001 and 002 not found: %v", old)
	}
	if err := dbmigrate.Migrate(ctx, db, old, "derived"); err != nil {
		t.Fatal(err)
	}
	const view = "/cat/at/1abc/children"
	c0 := NewCache(4, db)
	if _, err := c0.Put(ctx, view, "cat", "1abc", Stored{Body: []byte("sealed by v0.27.0"), Tags: "ns:cat"}); err != nil {
		t.Fatal(err)
	}

	c := NewCache(4, db)
	if err := c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if st, ok := c.Get(ctx, view); ok {
		t.Fatalf("a view stored by v0.27.0 served after the upgrade: %q", st.Body)
	}
	for _, table := range []string{"sealed_views", "sealed_view_tags"} {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: %d rows left (%v)", table, n, err)
		}
	}
	if _, err := c.Put(ctx, view, "cat", "1abc", Stored{Body: []byte("new"), Tags: "ns:cat"}); err != nil {
		t.Fatal(err)
	}
	c2 := NewCache(4, db)
	if err := c2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if st, ok := c2.Get(ctx, view); !ok || string(st.Body) != "new" {
		t.Fatalf("a view stored since the upgrade: %q %v", st.Body, ok)
	}
}
