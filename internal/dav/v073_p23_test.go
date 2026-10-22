package dav_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// Spec v0.73, Addendum H (gateways): copies, moves and names.

// Editors' and systems' own files are scratch files, kept in the gateway
// and never written to the core (§H.6): since v0.56 also LibreOffice's
// lock files (.~lock.*#), vim's *.swo and *.swx and sed -i's sedXXXXXX,
// in the flat view and in a tree. An existing file of such a name is a
// real file, read and written as one: an existing name wins (GW-13).
func TestV073ScratchNamesKeptInMemory(t *testing.T) {
	t.Parallel()
	names := []string{".~lock.report.odt#", "a.swo", ".notes.md.swx", "sedab12cd", "sedAb12cd"}
	f := newEnv(t, []string{"docs"}, nil, nil)
	for _, n := range names {
		p := "/docs/" + url.PathEscape(n)
		f.expect(f.do("PUT", p, "scratch "+n), 201, "PUT "+n)
		if g := f.expect(f.do("GET", p, ""), 200, "GET "+n); g.body != "scratch "+n {
			t.Fatalf("GET %s: %q", n, g.body)
		}
	}
	if got := f.liveNames("docs"); len(got) != 0 {
		t.Fatalf("scratch files reached the core: %q", got)
	}
	f.rawDoc("docs", "keep.swo", "text/plain", []byte("real"), nil)
	if g := f.expect(f.do("GET", "/docs/keep.swo", ""), 200, "GET a real keep.swo"); g.body != "real" {
		t.Fatalf("keep.swo %q", g.body)
	}
	f.expect(f.do("PUT", "/docs/keep.swo", "edited"), 201, "PUT over a real keep.swo")
	if _, data := f.rawOf("docs", "keep.swo"); string(data) != "edited" {
		t.Fatalf("keep.swo in the core %q", data)
	}

	e := treeEnv(t)
	e.create("matches", "sed", map[string]any{"title": "sed"})
	e.create("cat", "matches.sed", map[string]any{"title": "sedXYZ123", "parents": parents("cat", "season")})
	nodes := e.liveNames("cat")
	for _, n := range names {
		p := "/cat/Season/" + url.PathEscape(n)
		e.expect(e.do("PUT", p, "scratch "+n), 201, "PUT "+n+" in a tree")
	}
	sameStrings(t, "catalog nodes", e.liveNames("cat"), nodes)
	sameStrings(t, "matches", e.liveNames("matches"), []string{"derby", "sed"})
	if g := e.expect(e.do("GET", "/cat/Season/sedXYZ123", ""), 200, "GET a real file named like sed's"); g.body != rendered(map[string]any{"title": "sed"}) {
		t.Fatalf("sedXYZ123 %q", g.body)
	}
	e.expect(e.do("PUT", "/cat/Season/sedXYZ123", `{"title": "edited"}`), 201, "PUT over it")
	_, doc := e.load("matches", "sed")
	sameJSON(t, doc, map[string]any{"title": "edited"})
}

// Titles may hold Cf characters other than the bidirectional controls:
// a file named with a zero-width joiner, a soft hyphen or an LRM is made
// and listed as named, one with U+202E or U+2066 is refused, and one
// another tool wrote with a bidirectional control is shown escaped
// (§H.2 "Titles", GW-15).
func TestV073TitlesWithFormatCharacters(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	e.create("matches", "spoof", map[string]any{"t": 1})
	e.create("cat", "matches.spoof", map[string]any{"title": "a\u202eb.json", "parents": parents("cat", "empty")})
	for _, n := range []string{"a\u200db.txt", "co\u00adop.md", "x\u200ey.json"} {
		e.expect(e.do("PUT", "/cat/Season/"+url.PathEscape(n), `{"n": 1}`), 201, "PUT "+n)
		e.titled("cat", n)
	}
	sameStrings(t, "Season", names(e.propfind("/cat/Season/"), "/cat/Season/"), []string{"a\u200db.txt", "co\u00adop.md", "derby.json", "x\u200ey.json"})
	for _, n := range []string{"rtl\u202eexe.txt", "iso\u2066late.txt"} {
		r := e.expect(e.do("PUT", "/cat/Season/"+url.PathEscape(n), "x"), 403, "PUT "+n)
		if !strings.Contains(r.body, "bidirectional") {
			t.Fatalf("PUT %s: %s", n, r.body)
		}
	}
	sameStrings(t, "Empty", names(e.propfind("/cat/Empty/"), "/cat/Empty/"), []string{"a%E2%80%AEb.json"})
}

// A COPY or MOVE of a file onto an existing folder is 403, not the 405 a
// PUT onto one gets, and 412 with Overwrite: F (§H.5 "Move onto an
// existing file", GW-9); a folder moved onto a file is 403 and 412 too
// (GW-10).
func TestV073FileOntoFolder(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	hd, _ := e.load("matches", "derby")
	for _, m := range []string{"COPY", "MOVE"} {
		r := e.expect(e.do(m, "/cat/Season/derby.json", "", "Destination", "/cat/Empty"), 403, m+" of a file onto a folder")
		if !strings.Contains(r.body, "folder") {
			t.Fatalf("%s onto a folder: %s", m, r.body)
		}
		e.expect(e.do(m, "/cat/Season/derby.json", "", "Destination", "/cat/Empty", "Overwrite", "F"), 412, m+" of a file onto a folder, Overwrite: F")
		e.expect(e.do(m, "/cat/Season/derby.json", "", "Destination", "/cat"), 403, m+" of a file onto a tree's top level")
	}
	e.expect(e.do("PUT", "/cat/Empty", "x"), 405, "PUT onto a folder")
	e.expect(e.do("MOVE", "/cat/Empty", "", "Destination", "/cat/Season/derby.json"), 403, "MOVE of a folder onto a file")
	e.expect(e.do("MOVE", "/cat/Empty", "", "Destination", "/cat/Season/derby.json", "Overwrite", "F"), 412, "MOVE of a folder onto a file, Overwrite: F")
	e.expectLive("matches", "derby", hd, "the file")
	e.nodeDoc("cat", "empty")
	sameStrings(t, "Empty", names(e.propfind("/cat/Empty/"), "/cat/Empty/"), nil)
}

// A refused COPY onto a file sets the guard a refused PUT sets (§H.6
// "Delete, then write"): the user's DELETE of that path within 10 seconds
// is 409, once; so does a COPY to another case of a sibling's name
// (§H.2 "Siblings"), whose DELETE would otherwise delete the sibling
// (GW-12).
func TestV073GuardAfterRefusedCopy(t *testing.T) {
	t.Parallel()
	e := guardEnv(t, newClock())
	e.create("docs", "copy", map[string]any{"a": "1"})
	h, _ := e.load("docs", "copy")
	e.expect(e.do("PUT", "/docs/.goutputstream-copy", `{"a": "2"`), 201, "a scratch file that isn't JSON")
	e.expect(e.do("COPY", "/docs/.goutputstream-copy", "", "Destination", "/docs/copy.json"), 400, "COPY onto a JSON file")
	e.expectGuarded("/docs/copy.json", "DELETE after the refused COPY")
	e.expectLive("docs", "copy", h, "after the guarded DELETE")
	e.expect(e.do("DELETE", "/docs/copy.json", ""), 204, "DELETE again")
	e.expectTombstoned("docs", "copy", "after the second DELETE")

	t2 := treeEnv(t)
	hd, _ := t2.load("matches", "derby")
	t2.expect(t2.do("PUT", "/cat/Empty/notes.json", `{"n": 1}`), 201, "PUT notes.json")
	r := t2.expect(t2.do("COPY", "/cat/Empty/notes.json", "", "Destination", "/cat/Season/Derby.JSON"), 409, "COPY to another case of derby.json")
	if !strings.Contains(r.body, "derby.json") {
		t.Fatalf("COPY to a case variant: %s", r.body)
	}
	r = t2.expect(t2.do("DELETE", "/cat/Season/Derby.JSON", ""), 409, "rclone's cleanup DELETE of the case variant")
	if !strings.Contains(r.body, "refused save") {
		t.Fatalf("DELETE after a refused case variant: %s", r.body)
	}
	t2.expectLive("matches", "derby", hd, "derby after the guarded DELETE")
	if hn, _ := t2.load("cat", "matches.derby"); hn.State != client.Live {
		t.Fatalf("derby's placement %v", hn.State)
	}
}

// Placements of items in namespaces the catalog doesn't trust are left
// out when listing from the node documents too, as through a tree service
// (§H.2 "Untrusted namespaces", §B.5): not listed nor found by name, and
// no content of the folder they are in, which deletes them first as the
// dangling placements they are (§H.5 "Delete a folder", GW-21).
func TestV073UntrustedPlacementsLeftOut(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	must(e.c.CreateNamespace(e.ctx, "secret", map[string]any{"read": "public"}))
	e.create("secret", "plans", map[string]any{"launch": "monday"})
	e.create("cat", "secret.plans", map[string]any{"title": "plans.json", "parents": parents("cat", "empty")})
	sameStrings(t, "Empty", names(e.propfind("/cat/Empty/"), "/cat/Empty/"), nil)
	e.expect(e.do("GET", "/cat/Empty/plans.json", ""), 404, "GET the untrusted placement")
	e.expect(e.do("DELETE", "/cat/Empty/plans.json", ""), 404, "DELETE the untrusted placement")
	e.expect(e.do("DELETE", "/cat/Empty", ""), 204, "DELETE of the folder that holds it")
	e.expectTombstoned("cat", "empty", "the folder")
	e.expectTombstoned("cat", "secret.plans", "the untrusted placement, dangling")
	_, doc := e.load("secret", "plans")
	sameJSON(t, doc, map[string]any{"launch": "monday"})
}
