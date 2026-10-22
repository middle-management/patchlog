package dav_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
)

// Spec v0.73, Addendum H (gateways): copies, moves and names.

// treeDocsEnv is treeEnv with flat namespace docs served too: the flat
// view of matches, the tree's files.ns, is read-only (§H.2 "A file tree
// is a catalog"), and docs, which no tree served owns, is written in the
// flat view.
func treeDocsEnv(t *testing.T, with ...func(*clienttest.Options, *dav.Options)) *env {
	e := newEnv(t, []string{"docs", "matches"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("matches")}}, with...)
	e.create("matches", "derby", map[string]any{"title": "Derby"})
	e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	e.create("cat", "season", map[string]any{"title": "Season", "parents": parents("cat", "root")})
	e.create("cat", "empty", map[string]any{"title": "Empty", "parents": parents("cat", "root")})
	e.create("cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")})
	return e
}

// docsNS creates flat namespace docs beside a's tree, under a's key,
// holding derby and cup: no tree owns it, so the gateway writes it in the
// flat view, where the tree's files.ns, matches, is read-only (§H.2). It
// returns a client writing there.
func (a *authTree) docsNS(t *testing.T) *client.Client {
	t.Helper()
	must(a.s.Client(t, client.WithBearer(a.s.OperatorGrant(t, "docs"))).CreateNamespace(a.ctx, "docs", map[string]any{"read": "grant", "keys": []any{a.k.Entry("*")}}))
	w := a.s.Client(t, client.WithBearer(a.k.Grant(t, a.s.Now(), "user:w", []string{"docs"}, []string{"read", "create", "append", "delete"})))
	for _, n := range []string{"derby", "cup"} {
		must(w.CreateDoc(a.ctx, "docs", n, map[string]any{"title": n}))
	}
	return w
}

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

// A file tree owns the items of its files.ns (§H.2 "A file tree is a
// catalog"): a gateway that also serves files.ns flat serves it
// read-only, its files read and copied out as anywhere, but PUT, DELETE,
// MKCOL and LOCK there, a MOVE into or out of it, and a COPY into it are
// 403, nothing written; the tree's own writes, and a flat namespace no
// tree owns, are as before (GW-22).
func TestV073FilesNSReadOnlyFlat(t *testing.T) {
	t.Parallel()
	e := treeDocsEnv(t)
	hd, _ := e.load("matches", "derby")
	e.expect(e.do("GET", "/matches/derby.json", ""), 200, "GET in the read-only flat view")
	sameStrings(t, "matches", names(e.propfind("/matches/"), "/matches/"), []string{"derby.json"})
	lock := `<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`
	for _, c := range []struct {
		method, path, body string
		hdr                []string
	}{
		{"PUT", "/matches/x.json", `{"a": 1}`, nil},
		{"PUT", "/matches/derby.json", `{"title": "mine"}`, nil},
		{"PUT", "/matches/.x.swp", "swap", nil},
		{"DELETE", "/matches/derby.json", "", nil},
		{"MKCOL", "/matches/.TemporaryItems", "", nil},
		{"LOCK", "/matches/new.md", lock, nil},
		{"MOVE", "/matches/derby.json", "", []string{"Destination", "/matches/d2.json"}},
		{"MOVE", "/matches/derby.json", "", []string{"Destination", "/cat/Empty/moved.json"}},
		{"MOVE", "/matches/derby.json", "", []string{"Destination", "/docs/moved.json"}},
		{"MOVE", "/cat/Season/derby.json", "", []string{"Destination", "/matches/moved.json"}},
		{"COPY", "/cat/Season/derby.json", "", []string{"Destination", "/matches/copy.json"}},
		{"COPY", "/docs/x.json", "", []string{"Destination", "/matches/copy.json"}},
	} {
		r := e.expect(e.do(c.method, c.path, c.body, c.hdr...), 403, c.method+" "+c.path+" "+strings.Join(c.hdr, " "))
		if !strings.Contains(r.body, "read-only") || !strings.Contains(r.body, "file tree cat") {
			t.Fatalf("%s %s: %q", c.method, c.path, r.body)
		}
	}
	e.expectLive("matches", "derby", hd, "derby after the refusals")
	sameStrings(t, "matches", e.liveNames("matches"), []string{"derby"})
	if hn, _ := e.load("cat", "matches.derby"); hn.State != client.Live {
		t.Fatalf("derby's placement %v", hn.State)
	}

	e.expect(e.do("COPY", "/matches/derby.json", "", "Destination", "/cat/Empty/copy.json"), 201, "COPY out of the read-only flat view")
	e.expect(e.do("COPY", "/matches/derby.json", "", "Destination", "/docs/copy.json"), 201, "COPY out of it to a flat namespace")
	e.expect(e.do("PUT", "/cat/Season/new.json", `{"n": 1}`), 201, "PUT in the tree")
	e.expect(e.do("PUT", "/docs/x.json", `{"a": 1}`), 201, "PUT in a flat namespace no tree owns")
	e.expect(e.do("DELETE", "/docs/x.json", ""), 204, "DELETE there")
	if got := e.liveNames("matches"); len(got) != 3 {
		t.Fatalf("matches %q, want derby and the tree's two new items", got)
	}
}

// A PDF (a raw file stored as exactly application/pdf) is served, whole
// or in part, without the sandbox, which blanks browsers' PDF viewers,
// still with nosniff, and as an attachment unless the deployment opts
// into inline display; every other answer keeps the sandbox: an error, a
// 304, another type, a .pdf name of other bytes (§7.8, §H.6 "Headers",
// GW-25).
func TestV073PDFWithoutSandbox(t *testing.T) {
	t.Parallel()
	pdf := "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n"
	for _, inline := range []bool{false, true} {
		e := newEnv(t, []string{"docs"}, nil, nil, func(_ *clienttest.Options, o *dav.Options) { o.InlinePDF = inline })
		e.rawDoc("docs", "paper.pdf", "application/pdf", []byte(pdf), nil)
		e.rawDoc("docs", "fake.pdf", "application/octet-stream", []byte(pdf), nil)
		disp := "attachment"
		if inline {
			disp = ""
		}
		g := e.expect(e.do("GET", "/docs/paper.pdf", ""), 200, "GET a PDF")
		r := e.expect(e.do("GET", "/docs/paper.pdf", "", "Range", "bytes=0-3"), 206, "GET part of a PDF")
		hd := e.expect(e.do("HEAD", "/docs/paper.pdf", ""), 200, "HEAD a PDF")
		for _, a := range []resp{g, r, hd} {
			if a.header.Get("Content-Security-Policy") != "" || a.header.Get("X-Content-Type-Options") != "nosniff" || a.header.Get("Content-Disposition") != disp {
				t.Fatalf("inline %v: a PDF's %d: %v", inline, a.status, a.header)
			}
		}
		for _, a := range []resp{
			e.expect(e.do("GET", "/docs/paper.pdf", "", "If-None-Match", g.header.Get("ETag")), 304, "a PDF's 304"),
			e.expect(e.do("GET", "/docs/paper.pdf", "", "If-Match", `"other"`), 412, "a PDF's 412"),
			e.expect(e.do("GET", "/docs/paper.pdf", "", "Range", "bytes=900-999"), 416, "a PDF's 416"),
			e.expect(e.do("GET", "/docs/fake.pdf", ""), 200, "a .pdf of another type"),
			e.expect(e.do("PROPFIND", "/docs/", "", "Depth", "1"), 207, "a listing"),
		} {
			if a.header.Get("Content-Security-Policy") != "sandbox" || a.header.Get("X-Content-Type-Options") != "nosniff" || a.header.Get("Content-Disposition") != "" {
				t.Fatalf("inline %v: a %d: %v", inline, a.status, a.header)
			}
		}
	}
}
