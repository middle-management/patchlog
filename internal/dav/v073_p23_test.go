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

// childOf is the live node of catalog cat titled title in folder parent:
// its name and document.
func (e *env) childOf(cat, parent, title string) (string, map[string]any) {
	e.t.Helper()
	for _, n := range e.liveNames(cat) {
		d := e.nodeDoc(cat, n)
		if d["title"] != title {
			continue
		}
		ps, _ := d["parents"].([]any)
		for _, p := range ps {
			if m, _ := p.(map[string]any); m["href"] == "/r/"+cat+"/"+parent {
				return n, d
			}
		}
	}
	e.t.Fatalf("%s: no live node titled %q in %s", cat, title, parent)
	return "", nil
}

// noChild fails if catalog cat has a live node titled title in folder
// parent.
func (e *env) noChild(cat, parent, title string) {
	e.t.Helper()
	for _, n := range e.liveNames(cat) {
		d := e.nodeDoc(cat, n)
		ps, _ := d["parents"].([]any)
		for _, p := range ps {
			if m, _ := p.(map[string]any); m["href"] == "/r/"+cat+"/"+parent && d["title"] == title {
				e.t.Fatalf("%s: %s is titled %q in %s", cat, n, title, parent)
			}
		}
	}
}

// A COPY of a folder in a tree makes a new folder node titled with the
// Destination's last segment, without the source's $access, then copies
// its visible children into it one by one, files as new items and
// folders likewise; Depth: 0 copies the folder alone. Onto an existing
// folder or file it is 403 (412 with Overwrite: F), and into itself or
// into the flat view, which has no folders, 403. A folder that carries
// $access or sits under one isn't copied (F-H12); met part-way, it is
// that child's 403, what was copied before it staying (§H.5 "Copy",
// GW-7).
func TestV073FolderCopy(t *testing.T) {
	t.Parallel()
	e := treeDocsEnv(t)
	must(e.c.CreateNamespace(e.ctx, "secret", map[string]any{"read": "public"}))
	e.create("secret", "plans", map[string]any{"launch": "monday"})
	e.create("cat", "secret.plans", map[string]any{"title": "plans.json", "parents": parents("cat", "season")})
	e.create("cat", "sub", map[string]any{"title": "Sub", "parents": parents("cat", "season")})
	e.create("matches", "inner", map[string]any{"n": "inner"})
	e.create("cat", "matches.inner", map[string]any{"title": "inner.json", "parents": parents("cat", "sub")})
	e.rawDoc("matches", "pic", "image/png", []byte("\x89PNG pixels"), nil)
	e.create("cat", "matches.pic", map[string]any{"title": "pic.png", "parents": parents("cat", "season")})
	access := map[string]any{"group:desk": []any{"reader"}}
	e.create("cat", "locked", map[string]any{"title": "Locked", "parents": parents("cat", "root"), "$access": access})
	e.create("cat", "under", map[string]any{"title": "Under", "parents": parents("cat", "locked")})
	e.create("cat", "outer", map[string]any{"title": "Outer", "parents": parents("cat", "root")})
	e.create("matches", "a", map[string]any{"n": "a"})
	e.create("cat", "matches.a", map[string]any{"title": "a.json", "parents": parents("cat", "outer")})
	e.create("cat", "zinner", map[string]any{"title": "z-inner", "parents": parents("cat", "outer"), "$access": access})
	before := e.liveNames("matches")

	e.expect(e.do("COPY", "/cat/Season", "", "Destination", "/cat/Season%20copy"), 201, "COPY of a folder")
	folder, doc := e.childOf("cat", "root", "Season copy")
	if _, ok := doc["$access"]; ok || folder == "season" {
		t.Fatalf("the copy %s %v", folder, doc)
	}
	sameStrings(t, "the copy", names(e.propfind("/cat/Season%20copy/"), "/cat/Season copy/"), []string{"Sub/", "derby.json", "pic.png"})
	sameStrings(t, "Season", names(e.propfind("/cat/Season/"), "/cat/Season/"), []string{"Sub/", "derby.json", "pic.png"})
	node, _ := e.childOf("cat", folder, "derby.json")
	if ns, item, _ := strings.Cut(node, "."); ns != "matches" || item == "derby" {
		t.Fatalf("derby.json's copy %s", node)
	}
	_, item, _ := strings.Cut(node, ".")
	_, d := e.load("matches", item)
	sameJSON(t, d, map[string]any{"title": "Derby"})
	sub, _ := e.childOf("cat", folder, "Sub")
	inner, _ := e.childOf("cat", sub, "inner.json")
	_, item, _ = strings.Cut(inner, ".")
	_, d = e.load("matches", item)
	sameJSON(t, d, map[string]any{"n": "inner"})
	pic, _ := e.childOf("cat", folder, "pic.png")
	_, item, _ = strings.Cut(pic, ".")
	src, _ := e.rawOf("matches", "pic")
	if ref, data := e.rawOf("matches", item); string(data) != "\x89PNG pixels" || ref["type"] != "image/png" || ref["$blob"] != src["$blob"] {
		t.Fatalf("pic.png's copy %v %q, of %v", ref, data, src)
	}
	if got := len(e.liveNames("matches")); got != len(before)+3 {
		t.Fatalf("matches has %d documents, want %d: the untrusted placement copied?", got, len(before)+3)
	}

	e.expect(e.do("COPY", "/cat/Season", "", "Destination", "/cat/Bare", "Depth", "0"), 201, "COPY of a folder, Depth: 0")
	e.childOf("cat", "root", "Bare")
	sameStrings(t, "Bare", names(e.propfind("/cat/Bare/"), "/cat/Bare/"), nil)

	e.expect(e.do("COPY", "/cat/Season", "", "Destination", "/cat/Empty"), 403, "COPY onto a folder")
	e.expect(e.do("COPY", "/cat/Season", "", "Destination", "/cat/Empty", "Overwrite", "F"), 412, "COPY onto a folder, Overwrite: F")
	e.expect(e.do("COPY", "/cat/Empty", "", "Destination", "/cat/Season/derby.json"), 403, "COPY of a folder onto a file")
	e.expect(e.do("COPY", "/cat/Empty", "", "Destination", "/cat/Season/derby.json", "Overwrite", "F"), 412, "COPY of a folder onto a file, Overwrite: F")
	e.expect(e.do("COPY", "/cat/Season", "", "Destination", "/cat/Season/Sub/Again"), 403, "COPY of a folder into itself")
	e.expect(e.do("COPY", "/cat/Season", "", "Destination", "/docs/season"), 403, "COPY of a folder into the flat view")
	sameStrings(t, "Empty", names(e.propfind("/cat/Empty/"), "/cat/Empty/"), nil)
	e.noChild("cat", "sub", "Again")

	for _, src := range []string{"/cat/Locked", "/cat/Locked/Under"} {
		r := e.expect(e.do("COPY", src, "", "Destination", "/cat/Unlocked"), 403, "COPY of "+src)
		if !strings.Contains(r.body, "$access") {
			t.Fatalf("COPY of %s: %s", src, r.body)
		}
		e.noChild("cat", "root", "Unlocked")
	}
	r := e.expect(e.do("COPY", "/cat/Outer", "", "Destination", "/cat/Outer%20copy"), 403, "COPY of a folder holding one with $access")
	if !strings.Contains(r.body, "z-inner") {
		t.Fatalf("the part-way refusal: %s", r.body)
	}
	oc, _ := e.childOf("cat", "root", "Outer copy")
	e.childOf("cat", oc, "a.json")
	e.noChild("cat", oc, "z-inner")
}

// A MOVE of a folder to another tree makes the folder there, titled with
// the destination's name and without $access, moves its visible children
// into it one by one (files as moves across trees move them, their items
// naming their copies in $successor; folders likewise), and deletes the
// source folder once empty. A failure part-way leaves what was done and
// is answered as that child's MOVE (§H.5 "Copy", GW-8).
func TestV073FolderMoveAcrossTrees(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil, []string{"cat", "cat2"}, map[string]map[string]any{
		"cat":  {"catalog": treeCatalog("matches")},
		"cat2": {"catalog": treeCatalog("other")},
	})
	must(e.c.CreateNamespace(e.ctx, "matches", map[string]any{"read": "public"}))
	must(e.c.CreateNamespace(e.ctx, "other", map[string]any{"read": "public", "rules": []any{map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/doc/title", "exists": true}},
		"then": []any{map[string]any{"op": "test", "path": "/doc/title", "schema": map[string]any{"not": map[string]any{"const": "Refused"}}}}}}}))
	for _, cat := range []string{"cat", "cat2"} {
		e.create(cat, "root", map[string]any{"title": "Root", "parents": []any{}})
	}
	e.create("cat", "folder", map[string]any{"title": "Folder", "parents": parents("cat", "root"), "x-color": "red"})
	e.create("matches", "derby", map[string]any{"title": "Derby"})
	e.create("cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "folder")})
	e.create("cat", "sub", map[string]any{"title": "Sub", "parents": parents("cat", "folder")})
	e.create("matches", "inner", map[string]any{"n": "inner"})
	e.create("cat", "matches.inner", map[string]any{"title": "inner.json", "parents": parents("cat", "sub")})
	e.create("cat", "locked", map[string]any{"title": "Locked", "parents": parents("cat", "root"), "$access": map[string]any{"group:desk": []any{"reader"}}})
	e.create("cat", "part", map[string]any{"title": "Part", "parents": parents("cat", "root")})
	e.create("matches", "a", map[string]any{"title": "A"})
	e.create("cat", "matches.a", map[string]any{"title": "a.json", "parents": parents("cat", "part")})
	e.create("matches", "b", map[string]any{"title": "Refused"})
	e.create("cat", "matches.b", map[string]any{"title": "b.json", "parents": parents("cat", "part")})

	e.expect(e.do("MOVE", "/cat/Folder", "", "Destination", "/cat2/Moved"), 201, "MOVE of a folder to another tree")
	moved, doc := e.childOf("cat2", "root", "Moved")
	if _, ok := doc["$access"]; ok {
		t.Fatalf("the moved folder %v", doc)
	}
	sameStrings(t, "Moved", names(e.propfind("/cat2/Moved/"), "/cat2/Moved/"), []string{"Sub/", "derby.json"})
	node, _ := e.childOf("cat2", moved, "derby.json")
	_, item, _ := strings.Cut(node, ".")
	_, d := e.load("other", item)
	sameJSON(t, d, map[string]any{"title": "Derby"})
	if h, _ := e.load("matches", "derby"); h.State != client.Tombstoned || h.Successor != "/r/other/"+item {
		t.Fatalf("derby after the move %+v, copy %s", h, item)
	}
	sub, _ := e.childOf("cat2", moved, "Sub")
	e.childOf("cat2", sub, "inner.json")
	for _, n := range []string{"folder", "sub", "matches.derby", "matches.inner"} {
		e.expectTombstoned("cat", n, "the source's "+n)
	}
	sameStrings(t, "cat", names(e.propfind("/cat/"), "/cat/"), []string{"Locked/", "Part/"})

	hl, _ := e.load("cat", "locked")
	r := e.expect(e.do("MOVE", "/cat/Locked", "", "Destination", "/cat2/Locked"), 403, "MOVE of a folder with $access to another tree")
	if !strings.Contains(r.body, "$access") {
		t.Fatalf("MOVE of Locked: %s", r.body)
	}
	e.expectLive("cat", "locked", hl, "Locked after the refusal")
	e.noChild("cat2", "root", "Locked")

	r = e.expect(e.do("MOVE", "/cat/Part", "", "Destination", "/cat2/Part"), 422, "MOVE of a folder whose second file is refused there")
	if !strings.Contains(r.body, "rule") {
		t.Fatalf("the part-way refusal: %s", r.body)
	}
	part2, _ := e.childOf("cat2", "root", "Part")
	e.childOf("cat2", part2, "a.json")
	e.noChild("cat2", part2, "b.json")
	e.expectTombstoned("matches", "a", "a.json's item, moved")
	e.nodeDoc("cat", "part")
	e.nodeDoc("cat", "matches.b")
	sameStrings(t, "Part", names(e.propfind("/cat/Part/"), "/cat/Part/"), []string{"b.json"})

	e.expect(e.do("MOVE", "/cat/Part", "", "Destination", "/cat2/Part"), 403, "MOVE of a folder onto a folder in another tree")
	e.expect(e.do("MOVE", "/cat/Part", "", "Destination", "/cat2/Part", "Overwrite", "F"), 412, "MOVE of a folder onto a folder, Overwrite: F")
}

// Through a tree service a folder's COPY copies what the tree service
// lists in it, into the new folder it then lists (§H.3, §H.5 "Copy",
// GW-7).
func TestV073FolderCopyThroughTreeService(t *testing.T) {
	t.Parallel()
	e := treeEnv(t)
	e.create("cat", "sub", map[string]any{"title": "Sub", "parents": parents("cat", "season")})
	e.create("matches", "inner", map[string]any{"n": "inner"})
	e.create("cat", "matches.inner", map[string]any{"title": "inner.json", "parents": parents("cat", "sub")})
	tr := startTree(t, e.s, "cat")
	tr.caughtUp("cat", "matches")
	ts := treeDav(e, tr.http.URL)
	sameStrings(t, "Season", names(ts.propfind("/cat/Season/"), "/cat/Season/"), []string{"Sub/", "derby.json"})
	ts.expect(ts.do("COPY", "/cat/Season", "", "Destination", "/cat/Copy"), 201, "COPY of a folder through a tree service")
	sameStrings(t, "Copy", names(ts.propfind("/cat/Copy/"), "/cat/Copy/"), []string{"Sub/", "derby.json"})
	sameStrings(t, "Copy/Sub", names(ts.propfind("/cat/Copy/Sub/"), "/cat/Copy/Sub/"), []string{"inner.json"})
	if g := ts.expect(ts.do("GET", "/cat/Copy/Sub/inner.json", ""), 200, "GET the copy's file"); g.body != rendered(map[string]any{"n": "inner"}) {
		t.Fatalf("the copy's inner.json %q", g.body)
	}
	copied, _ := e.childOf("cat", "root", "Copy")
	if node, _ := e.childOf("cat", copied, "derby.json"); node == "matches.derby" {
		t.Fatal("the copy placed the source's item")
	}
}
