package dav_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
	"github.com/middle-management/patchlog/internal/seal"
)

// rawDoc creates raw document ns/name straight in the core, as another
// tool does: data as a blob of type typ, and a root that is its reference,
// with extra top-level members.
func (e *env) rawDoc(ns, name, typ string, data []byte, extra map[string]any) string {
	e.t.Helper()
	bid := must(e.c.UploadBlob(e.ctx, ns, name, typ, "", data))
	doc := map[string]any{"$blob": bid, "type": typ, "size": len(data)}
	for k, v := range extra {
		doc[k] = v
	}
	return e.create(ns, name, doc)
}

// rawOf is raw document ns/name's reference and the bytes of its blob,
// read straight from the core; it fails if the document isn't raw.
func (e *env) rawOf(ns, name string) (map[string]any, []byte) {
	e.t.Helper()
	_, doc := e.load(ns, name)
	bid := client.RawBlobOf(doc)
	if bid == "" {
		e.t.Fatalf("%s/%s isn't raw: %v", ns, name, doc)
	}
	m := doc.(map[string]any)
	nonce, _ := m["nonce"].(string)
	b := must(e.c.GetBlob(e.ctx, ns, name, bid, nonce))
	return m, b.Data
}

// patchPaths are the paths of a log entry's patch set.
func patchPaths(t *testing.T, ps any) []string {
	t.Helper()
	var out []string
	for _, p := range ps.([]any) {
		out = append(out, p.(map[string]any)["path"].(string))
	}
	return out
}

// Every file other than a JSON file is a raw document whose root is a
// blob reference to its bytes, typed by its extension (§H.1): created,
// read back byte for byte as its type, and edited by setting the
// reference's members, never the root, so other members ($successor)
// stay. A new .json file that isn't I-JSON is raw, and stays raw whatever
// it is saved with; a text file of JSON is raw too.
func TestRawFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01")
	for _, c := range []struct {
		name, ctype, typ string
		data             []byte
	}{
		{"notes.md", "text/plain", "text/markdown", []byte("# Notes\n\nSome *text*.\n")},
		{"logo.png", "", "image/png", png},
		{"paper.pdf", "application/octet-stream", "application/pdf", []byte("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n")},
		{"conf.json", "application/json", "application/json", []byte("{\n  // a comment\n  \"a\": 1,\n}\n")},
		{"big.json", "", "application/json", []byte(`{"n": 9007199254740993}`)},
		{"data.txt", "", "text/plain", []byte(`{"a": 1}`)},
	} {
		put := e.expect(e.do("PUT", "/docs/"+c.name, string(c.data), "Content-Type", c.ctype), 201, "PUT "+c.name)
		h, _ := e.load("docs", c.name)
		ref, data := e.rawOf("docs", c.name)
		if ref["type"] != c.typ || ref["size"] != float64(len(c.data)) || !bytes.Equal(data, c.data) || put.header.Get("ETag") != `"`+h.ID+`"` {
			t.Fatalf("%s: %v %q, ETag %s", c.name, ref, data, put.header.Get("ETag"))
		}
		g := e.expect(e.do("GET", "/docs/"+c.name, ""), 200, "GET "+c.name)
		if g.body != string(c.data) || g.header.Get("Content-Type") != c.typ || g.header.Get("ETag") != `"`+h.ID+`"` ||
			g.header.Get("X-Content-Type-Options") != "nosniff" || g.header.Get("Content-Security-Policy") != "sandbox" {
			t.Fatalf("GET %s: %q %v", c.name, g.body, g.header)
		}
		l := e.propfind("/docs/")["/docs/"+c.name]
		if l.size != strconv.Itoa(len(c.data)) || l.ctype != c.typ || l.etag != `"`+h.ID+`"` {
			t.Fatalf("%s listed %+v", c.name, l)
		}
	}
	for _, n := range []string{"conf", "big"} {
		if h, _ := e.load("docs", n); h.State != client.NotFound {
			t.Fatalf("a .json file that isn't I-JSON made JSON document %s", n)
		}
	}

	// An edit sets the reference's members; an unchanged save writes
	// nothing.
	h0, _ := e.load("docs", "notes.md")
	e.expect(e.do("PUT", "/docs/notes.md", "# Notes\n\nSome *text*.\n"), 201, "PUT unchanged")
	if h, _ := e.load("docs", "notes.md"); h.ID != h0.ID {
		t.Fatal("an unchanged save of a raw file wrote")
	}
	e.expect(e.do("PUT", "/docs/notes.md", "# Notes\n\nMore text.\n"), 201, "PUT edit")
	sameStrings(t, "edit", patchPaths(t, e.lastEntry("docs", "notes.md").Patches), []string{"/$blob", "/size"})
	if _, data := e.rawOf("docs", "notes.md"); string(data) != "# Notes\n\nMore text.\n" {
		t.Fatalf("edited %q", data)
	}

	// An existing raw .json keeps its kind, whatever it is saved with.
	e.expect(e.do("PUT", "/docs/conf.json", `{"a": 2}`), 201, "PUT JSON over a raw .json")
	if _, data := e.rawOf("docs", "conf.json"); string(data) != `{"a": 2}` {
		t.Fatalf("conf.json %q", data)
	}

	// Members of the root other than the reference stay.
	e.rawDoc("docs", "moved.txt", "text/plain", []byte("old"), map[string]any{"$successor": "notes.md"})
	e.expect(e.do("PUT", "/docs/moved.txt", "new"), 201, "PUT over a raw file with $successor")
	if ref, data := e.rawOf("docs", "moved.txt"); ref["$successor"] != "notes.md" || string(data) != "new" {
		t.Fatalf("moved.txt %v %q", ref, data)
	}
}

// A raw file's save compares its base with the head first: any change of
// its bytes in between is a conflict (409, nothing written), raw files
// having no paths to merge (§H.4); after a reload the save goes through.
// Its base is the revision If-Match names, else the one the user read.
func TestRawConflict(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.rawDoc("docs", "a.txt", "text/plain", []byte("one"), nil)
	g := e.expect(e.do("GET", "/docs/a.txt", ""), 200, "GET")
	h, _ := e.load("docs", "a.txt")
	bid := must(e.c.UploadBlob(e.ctx, "docs", "a.txt", "text/plain", "", []byte("theirs")))
	must(e.c.Append(e.ctx, "docs", "a.txt", h.ID, []any{replace("/$blob", bid), replace("/size", 6)}))
	h, _ = e.load("docs", "a.txt")
	r := e.expect(e.do("PUT", "/docs/a.txt", "mine"), 409, "PUT over their edit")
	if !strings.Contains(r.body, "/$blob") {
		t.Fatalf("409 %q", r.body)
	}
	e.expect(e.do("PUT", "/docs/a.txt", "mine", "If-Match", g.header.Get("ETag")), 409, "PUT If-Match the old revision")
	if h2, _ := e.load("docs", "a.txt"); h2.ID != h.ID {
		t.Fatal("a conflicting raw save wrote")
	}
	e.expect(e.do("GET", "/docs/a.txt", ""), 200, "reload")
	e.expect(e.do("PUT", "/docs/a.txt", "mine"), 201, "PUT after the reload")
	if _, data := e.rawOf("docs", "a.txt"); string(data) != "mine" {
		t.Fatalf("a.txt %q", data)
	}
}

// Where nonces are required (§C.7) a raw file's root carries a fresh
// $nonce beside the reference, and its blob a nonce (Blob-Nonce); a JSON
// file's root must be an object, which carries the $nonce, and any other
// is refused (422, saying why).
func TestRawNonces(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"priv"}, nil, map[string]map[string]any{"priv": {"nonce": "required"}})
	e.expect(e.do("PUT", "/priv/notes.md", "secret notes"), 201, "PUT")
	ref, data := e.rawOf("priv", "notes.md")
	n1, _ := ref["$nonce"].(string)
	if bn, _ := ref["nonce"].(string); len(n1) != 26 || len(bn) != 26 || string(data) != "secret notes" {
		t.Fatalf("created %v %q", ref, data)
	}
	if g := e.expect(e.do("GET", "/priv/notes.md", ""), 200, "GET"); g.body != "secret notes" {
		t.Fatalf("GET %q", g.body)
	}
	e.expect(e.do("PUT", "/priv/notes.md", "secret notes"), 201, "PUT unchanged")
	if en := e.lastEntry("priv", "notes.md"); en.Parent != "" {
		t.Fatal("an unchanged save wrote, nonces or not")
	}
	e.expect(e.do("PUT", "/priv/notes.md", "other notes"), 201, "PUT edit")
	ref, data = e.rawOf("priv", "notes.md")
	if ref["$nonce"] == n1 || string(data) != "other notes" {
		t.Fatalf("edited %v %q", ref, data)
	}
	r := e.expect(e.do("PUT", "/priv/list.json", `[1, 2]`), 422, "PUT a JSON array")
	if !strings.Contains(r.body, "root must be an object") {
		t.Fatalf("422 %q", r.body)
	}
	if h, _ := e.load("priv", "list"); h.State != client.NotFound {
		t.Fatal("a refused root was written")
	}
}

// A JSON file reads as its rendering (§H.1): the canonical text laid out
// as JSON.stringify(v, null, 2) lays it out, byte for byte (keys in JCS's
// order, those that look like array indices too; empty objects and arrays
// as {} and []; numbers as JCS writes them), without a fresh $nonce and a
// $successor of §8.1's form, with one final LF; its size is that.
func TestJSONRendering(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	doc := `{"b": true, "10": "ten", "2": [1, 2.50, -0, 1e21, 0.000001, 1E-7], "a": {"z": [], "y": {}, "x": [{}]},
		"s": "é\t \"", "": null, "$nonce": "` + seal.NewNonce() + `", "$successor": "other"}`
	e.create("docs", "x", json.RawMessage(doc))
	want := "{\n" +
		"  \"\": null,\n" +
		"  \"10\": \"ten\",\n" +
		"  \"2\": [\n" +
		"    1,\n" +
		"    2.5,\n" +
		"    0,\n" +
		"    1e+21,\n" +
		"    0.000001,\n" +
		"    1e-7\n" +
		"  ],\n" +
		"  \"a\": {\n" +
		"    \"x\": [\n" +
		"      {}\n" +
		"    ],\n" +
		"    \"y\": {},\n" +
		"    \"z\": []\n" +
		"  },\n" +
		"  \"b\": true,\n" +
		"  \"s\": \"é\\t \\\"\"\n" +
		"}\n"
	g := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
	if g.body != want || !strings.HasPrefix(g.header.Get("Content-Type"), "application/json") {
		t.Fatalf("GET %q %v\nwant %q", g.body, g.header, want)
	}
	if l := e.propfind("/docs/")["/docs/x.json"]; l.size != strconv.Itoa(len(want)) {
		t.Fatalf("listed %+v, want size %d", l, len(want))
	}
	// Saved back unchanged, it writes nothing, and the $successor stays.
	e.expect(e.do("PUT", "/docs/x.json", g.body), 201, "PUT unchanged")
	if en := e.lastEntry("docs", "x"); en.Parent != "" {
		t.Fatal("an unchanged save wrote")
	}
	e.expect(e.do("PUT", "/docs/x.json", strings.Replace(g.body, `"b": true`, `"b": false`, 1)), 201, "PUT edit")
	sameJSON(t, e.lastEntry("docs", "x").Patches, []any{replace("/b", false)})
	if _, doc := e.load("docs", "x"); doc.(map[string]any)["$successor"] != "other" {
		t.Fatalf("edited %v", doc)
	}
}

// A raw file's type is its extension's, else the upload's Content-Type
// without parameters unless it says nothing of the bytes, else
// application/octet-stream (§H.1); a copy's is its source's.
func TestFileTypes(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	for _, c := range []struct{ name, ctype, typ string }{
		{"main.go", "Text/X-Go; charset=utf-8", "text/x-go"},
		{"page.htm", "text/plain", "text/html"},
		{"data.yml", "", "application/yaml"},
		{"blob", "application/octet-stream", "application/octet-stream"},
		{"form", "multipart/form-data; boundary=x", "application/octet-stream"},
		{"posted", "application/x-www-form-urlencoded", "application/octet-stream"},
		{"bin", "binary/octet-stream", "application/octet-stream"},
		{"none", "", "application/octet-stream"},
		{"bad", "not a type", "application/octet-stream"},
		{"report.docx", "", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
	} {
		e.expect(e.do("PUT", "/docs/"+c.name, "bytes of "+c.name, "Content-Type", c.ctype), 201, "PUT "+c.name)
		if ref, _ := e.rawOf("docs", c.name); ref["type"] != c.typ {
			t.Fatalf("%s as %q: %v", c.name, c.ctype, ref)
		}
	}
	e.expect(e.do("COPY", "/docs/main.go", "", "Destination", "/docs/copy"), 201, "COPY")
	if ref, data := e.rawOf("docs", "copy"); ref["type"] != "text/x-go" || string(data) != "bytes of main.go" {
		t.Fatalf("copy %v %q", ref, data)
	}
	e.create("docs", "j", map[string]any{"a": 1})
	e.expect(e.do("COPY", "/docs/main.go", "", "Destination", "/docs/j.json", "Overwrite", "T"), 400, "COPY bytes over a JSON file")
}

// The flat view (§H.2): a raw document by its name, any other as
// {name}.json; where a raw x.json and a JSON document x both exist, the
// raw file keeps the name and the document is x (2).json, read and
// written as itself. A name a resource has is that resource's file
// whatever it looks like; a name another kind of file has can't be taken.
func TestFlatView(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"v": 1})
	e.rawDoc("docs", "x.json", "application/json", []byte("{not json"), nil)
	e.rawDoc("docs", "4913", "text/plain", []byte("a real file"), nil)
	e.create("docs", "notes.md", map[string]any{"json": true})
	e.rawDoc("docs", "pic", "image/png", []byte("png"), nil)
	sameStrings(t, "listing", names(e.propfind("/docs/"), "/docs/"), []string{"4913", "notes.md.json", "pic", "x (2).json", "x.json"})
	if b := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET the raw x.json").body; b != "{not json" {
		t.Fatalf("x.json %q", b)
	}
	if b := e.expect(e.do("GET", "/docs/x%20(2).json", ""), 200, "GET x (2).json").body; b != rendered(map[string]any{"v": 1}) {
		t.Fatalf("x (2).json %q", b)
	}
	if b := e.expect(e.do("GET", "/docs/4913", ""), 200, "GET 4913").body; b != "a real file" {
		t.Fatalf("4913 %q", b)
	}
	e.expect(e.do("PUT", "/docs/x%20(2).json", `{"v": 2}`), 201, "PUT x (2).json")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 2})
	e.expect(e.do("PUT", "/docs/4913", "edited"), 201, "PUT 4913")
	if _, data := e.rawOf("docs", "4913"); string(data) != "edited" {
		t.Fatalf("4913 %q", data)
	}

	// Taken names: notes.md is a JSON document's (notes.md.json), pic a raw
	// one's, so pic.json can't be JSON document pic, only raw file pic.json.
	r := e.expect(e.do("PUT", "/docs/notes.md", "# text"), 409, "PUT notes.md")
	if !strings.Contains(r.body, "notes.md.json") {
		t.Fatalf("409 %q", r.body)
	}
	e.expect(e.do("PUT", "/docs/pic.json", `{"a": 1}`), 409, "PUT JSON as pic.json")
	e.expect(e.do("PUT", "/docs/pic.json", `not JSON`), 201, "PUT bytes as pic.json")
	e.rawOf("docs", "pic.json")

	// A new valid name is a file in the core; a scratch name isn't (§H.6).
	e.expect(e.do("PUT", "/docs/new.txt", "new"), 201, "PUT new.txt")
	e.rawOf("docs", "new.txt")
	e.expect(e.do("PUT", "/docs/new.txt.swp", "swap"), 201, "PUT a swap file")
	if h, _ := e.load("docs", "new.txt.swp"); h.State != client.NotFound {
		t.Fatal("a scratch file reached the core")
	}

	e.expect(e.do("DELETE", "/docs/x%20(2).json", ""), 204, "DELETE x (2).json")
	if h, _ := e.load("docs", "x"); h.State != client.Tombstoned {
		t.Fatalf("x is %v", h.State)
	}
	if h, _ := e.load("docs", "x.json"); h.State != client.Live {
		t.Fatalf("x.json is %v", h.State)
	}
	sameStrings(t, "listing", names(e.propfind("/docs/"), "/docs/"), []string{"4913", "new.txt", "new.txt.swp", "notes.md.json", "pic", "pic.json", "x.json"})
}

// Editors' saves of raw files: vim's backup copies the bytes into scratch
// and the write that follows edits the file; an atomic save's temporary
// file moved over it commits its bytes, typed as the file's name says; a
// save that deletes the file first restores it, as the raw file it was.
func TestRawEditorSaves(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.expect(e.do("PUT", "/docs/notes.md", "v1"), 201, "PUT")
	e.expect(e.do("MOVE", "/docs/notes.md", "", "Destination", "/docs/notes.md~"), 201, "vim: backup")
	if b := e.expect(e.do("GET", "/docs/notes.md~", ""), 200, "GET backup").body; b != "v1" {
		t.Fatalf("backup %q", b)
	}
	e.expect(e.do("PUT", "/docs/notes.md", "v2"), 201, "vim: write")
	e.expect(e.do("DELETE", "/docs/notes.md~", ""), 204, "vim: backup gone")
	e.expect(e.do("PUT", "/docs/.goutputstream-ABC", "v3", "Content-Type", "text/plain"), 201, "gedit: temporary file")
	e.expect(e.do("MOVE", "/docs/.goutputstream-ABC", "", "Destination", "/docs/notes.md"), 204, "gedit: over the file")
	ref, data := e.rawOf("docs", "notes.md")
	if ref["type"] != "text/markdown" || string(data) != "v3" {
		t.Fatalf("notes.md %v %q", ref, data)
	}
	if n := len(must(e.c.Log(e.ctx, "docs", "notes.md", "", ""))); n != 3 {
		t.Fatalf("%d revisions", n)
	}
	// A file manager's duplicate beside it is a scratch file until it is
	// named: then a new file, of its source's type unless its name says.
	e.expect(e.do("COPY", "/docs/notes.md", "", "Destination", "/docs/notes%20copy.md"), 201, "Duplicate")
	e.expect(e.do("MOVE", "/docs/notes%20copy.md", "", "Destination", "/docs/plan.txt"), 201, "named")
	if ref, data := e.rawOf("docs", "plan.txt"); ref["type"] != "text/plain" || string(data) != "v3" {
		t.Fatalf("plan.txt %v %q", ref, data)
	}
	e.expect(e.do("COPY", "/docs/notes.md", "", "Destination", "/docs/notes%20copy%202.md"), 201, "Duplicate")
	e.expect(e.do("MOVE", "/docs/notes%20copy%202.md", "", "Destination", "/docs/plan"), 201, "named")
	if ref, _ := e.rawOf("docs", "plan"); ref["type"] != "text/markdown" {
		t.Fatalf("plan %v", ref)
	}

	// Delete, then write: the raw x.json comes back raw, though its new
	// content is JSON.
	e.expect(e.do("PUT", "/docs/x.json", "not JSON"), 201, "PUT a raw x.json")
	e.expect(e.do("DELETE", "/docs/x.json", ""), 204, "DELETE it")
	e.expect(e.do("PUT", "/docs/x.json", `{"now": "JSON"}`), 201, "PUT it again")
	if h, _ := e.load("docs", "x"); h.State != client.NotFound {
		t.Fatal("the write after the delete made JSON document x")
	}
	if _, data := e.rawOf("docs", "x.json"); string(data) != `{"now": "JSON"}` {
		t.Fatalf("x.json %q", data)
	}
	log := must(e.c.Log(e.ctx, "docs", "x.json", "", ""))
	if len(log) != 3 || log[1].Kind != "tombstone" {
		t.Fatalf("log %+v", log)
	}
}

// A raw file is served by the gateway itself (§H.6 "Raw bytes"): its
// bytes from its blob, as its type, under the revision's ETag, with
// nosniff and a sandbox policy, ranges and conditional requests included,
// and a HEAD reads no blob.
func TestRawBytes(t *testing.T) {
	t.Parallel()
	var blobs atomic.Int64
	e := newEnv(t, []string{"docs"}, nil, nil, func(c *clienttest.Options, _ *dav.Options) {
		c.Wrap = func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && strings.Contains(r.URL.Path, "/blob/") {
					blobs.Add(1)
				}
				h.ServeHTTP(w, r)
			})
		}
	})
	data := strings.Repeat("0123456789", 1000)
	rev := e.rawDoc("docs", "page.html", "text/html", []byte(data), nil)
	tag := `"` + rev + `"`
	hd := e.expect(e.do("HEAD", "/docs/page.html", ""), 200, "HEAD")
	if hd.header.Get("Content-Length") != strconv.Itoa(len(data)) || hd.header.Get("ETag") != tag || hd.header.Get("Content-Type") != "text/html" ||
		hd.header.Get("X-Content-Type-Options") != "nosniff" || hd.header.Get("Content-Security-Policy") != "sandbox" || blobs.Load() != 0 {
		t.Fatalf("HEAD %v, %d blob reads", hd.header, blobs.Load())
	}
	g := e.expect(e.do("GET", "/docs/page.html", "", "Range", "bytes=5-14"), 206, "GET a range")
	if g.body != "5678901234" || g.header.Get("Content-Range") != "bytes 5-14/"+strconv.Itoa(len(data)) || g.header.Get("ETag") != tag {
		t.Fatalf("range %q %v", g.body, g.header)
	}
	g = e.expect(e.do("GET", "/docs/page.html", "", "Range", "bytes=-3"), 206, "GET a suffix")
	if g.body != "789" {
		t.Fatalf("suffix %q", g.body)
	}
	e.expect(e.do("GET", "/docs/page.html", "", "If-None-Match", tag), 304, "GET If-None-Match")
	if g := e.expect(e.do("GET", "/docs/page.html", ""), 200, "GET"); g.body != data {
		t.Fatalf("GET %d bytes", len(g.body))
	}
	e.expect(e.do("GET", "/docs/page.html", "", "If-Range", `"1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, "Range", "bytes=0-0"), 200, "GET If-Range another revision")
}

// A PUT with Content-Range (a partial write) is 400 and writes nothing
// (§H.4).
func TestPartialPut(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.expect(e.do("PUT", "/docs/a.txt", "whole"), 201, "PUT")
	h, _ := e.load("docs", "a.txt")
	for _, p := range []string{"/docs/a.txt", "/docs/b.txt", "/docs/c.json"} {
		r := e.expect(e.do("PUT", p, "part", "Content-Range", "bytes 0-3/10"), 400, "PUT with Content-Range "+p)
		if !strings.Contains(r.body, "Content-Range") {
			t.Fatalf("400 %q", r.body)
		}
	}
	if h2, _ := e.load("docs", "a.txt"); h2.ID != h.ID {
		t.Fatal("a partial write wrote")
	}
	for _, n := range []string{"b.txt", "c", "c.json"} {
		if h, _ := e.load("docs", n); h.State != client.NotFound {
			t.Fatalf("a partial write created %s", n)
		}
	}
}

// After a save merged with others' edits, the next HEAD is answered in
// full too, whatever validators it carries (§H.1 "Identity").
func TestHeadAfterMergedSave(t *testing.T) {
	t.Parallel()
	e := newEnv(t, []string{"docs"}, nil, nil)
	e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
	body := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
	e.theirs("docs", "x", replace("/b", "theirs"))
	e.expect(e.do("PUT", "/docs/x.json", edit(t, body, `"a": "1"`, `"a": "mine"`)), 201, "PUT merged")
	h, _ := e.load("docs", "x")
	tag := `"` + h.ID + `"`
	e.expect(e.do("HEAD", "/docs/x.json", "", "If-None-Match", tag), 200, "HEAD after the merged save")
	e.expect(e.do("GET", "/docs/x.json", "", "If-None-Match", tag), 200, "GET after the merged save")
	e.expect(e.do("HEAD", "/docs/x.json", "", "If-None-Match", tag), 304, "HEAD after the GET")
}

// counting is a flat environment whose core counts the requests the
// WebDAV server makes (its writes carry X-Author dav), and strips what
// strip names from /heads pages ("created") and revisions
// ("Last-Modified").
func counting(t *testing.T, strip map[string]bool, with ...func(*clienttest.Options, *dav.Options)) (*env, func() int64) {
	var n atomic.Int64
	wrap := func(c *clienttest.Options, _ *dav.Options) {
		c.Wrap = func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Author") == "dav" {
					n.Add(1)
				}
				if !strings.HasSuffix(r.URL.Path, "/heads") && !strings.Contains(r.URL.Path, "/rev/") {
					h.ServeHTTP(w, r)
					return
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r)
				body := rec.Body.Bytes()
				if strip["created"] && strings.HasSuffix(r.URL.Path, "/heads") {
					var page map[string]any
					must(0, json.Unmarshal(body, &page))
					for _, it := range page["items"].([]any) {
						delete(it.(map[string]any), "created")
					}
					body = must(json.Marshal(page))
				}
				for k, v := range rec.Header() {
					if k != "Content-Length" && !(k == "Last-Modified" && strip["Last-Modified"]) {
						w.Header()[k] = v
					}
				}
				w.WriteHeader(rec.Code)
				w.Write(body)
			})
		}
	}
	e := newEnv(t, []string{"docs"}, nil, nil, append([]func(*clienttest.Options, *dav.Options){wrap}, with...)...)
	return e, func() int64 { return n.Swap(0) }
}

// A flat directory lists the head rows of /heads (§H.3): ETag from the
// row's target, time from its created, a JSON file's size its rendering's
// and a raw file's its reference's, which take each revision's document
// once, for good: listed again, only the heads are read, though the
// documents don't fit the cache. Rows without created take Last-Modified
// from the document read; with neither, the time is when the user first
// saw the revision.
func TestFlatListing(t *testing.T) {
	t.Parallel()
	e, reqs := counting(t, nil, func(_ *clienttest.Options, o *dav.Options) { o.CacheBytes = 1 })
	ra := e.create("docs", "a", map[string]any{"title": "A"})
	rb := e.rawDoc("docs", "b.md", "text/markdown", []byte("# B"), nil)
	created := func(name string) string {
		return must(time.Parse(time.RFC3339Nano, e.lastEntry("docs", name).Created)).UTC().Format(http.TimeFormat)
	}
	check := func(l map[string]entry) {
		t.Helper()
		a, b := l["/docs/a.json"], l["/docs/b.md"]
		if a.etag != `"`+ra+`"` || a.size != strconv.Itoa(len(rendered(map[string]any{"title": "A"}))) || a.ctype != "application/json" || a.modified != created("a") {
			t.Fatalf("a.json %+v, created %s", a, created("a"))
		}
		if b.etag != `"`+rb+`"` || b.size != "3" || b.ctype != "text/markdown" || b.modified != created("b.md") {
			t.Fatalf("b.md %+v, created %s", b, created("b.md"))
		}
	}
	check(e.propfind("/docs/"))
	if n := reqs(); n > 6 {
		t.Fatalf("the first listing made %d requests", n)
	}
	check(e.propfind("/docs/"))
	if n := reqs(); n != 2 {
		t.Fatalf("listed again: %d requests, want the namespace's head and /heads", n)
	}

	// Without created, Last-Modified of the documents' reads.
	e2, _ := counting(t, map[string]bool{"created": true})
	e2.create("docs", "a", map[string]any{"title": "A"})
	want := must(time.Parse(time.RFC3339Nano, e2.lastEntry("docs", "a").Created)).UTC().Format(http.TimeFormat)
	if a := e2.propfind("/docs/")["/docs/a.json"]; a.modified != want {
		t.Fatalf("without created: %+v, want %s", a, want)
	}
	// Without either, when the user first saw it.
	seen := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
	e3, _ := counting(t, map[string]bool{"created": true, "Last-Modified": true}, func(_ *clienttest.Options, o *dav.Options) {
		o.Now = func() time.Time { return seen }
	})
	e3.create("docs", "a", map[string]any{"title": "A"})
	if a := e3.propfind("/docs/")["/docs/a.json"]; a.modified != seen.Format(http.TimeFormat) {
		t.Fatalf("without times: %+v", a)
	}
}

// A raw file's save (§H.4): compared first, its base with the head, so
// bytes someone changed and changed back between them are a conflict as
// a whole (raw files have no paths to merge) before anything is uploaded;
// over a blobSize the namespace sets it is 413 before any upload; and a
// 412 when the head moves after the upload (another program's edit of a
// member that isn't the bytes, a $nonce) is retried with the blob already
// pending, never uploaded twice, the reference's members set one by one,
// so the other member stays.
func TestRawSaves(t *testing.T) {
	t.Parallel()
	var uploads atomic.Int32
	var arm atomic.Bool
	var e *env
	theirNonce := seal.NewNonce()
	e = newEnv(t, []string{"docs", "small"}, nil, map[string]map[string]any{"small": {"limits": map[string]any{"blobSize": 8}}},
		func(c *clienttest.Options, _ *dav.Options) {
			c.Wrap = func(h http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == "PUT" && strings.Contains(r.URL.Path, "/blob/") && r.Header.Get("X-Author") != "other" {
						uploads.Add(1)
					}
					if r.Method == "PATCH" && r.URL.Path == "/r/docs/f.md" && r.Header.Get("If-Match") != "" && arm.CompareAndSwap(true, false) {
						hd, _ := e.load("docs", "f.md")
						must(e.c.Append(e.ctx, "docs", "f.md", hd.ID, []any{map[string]any{"op": "add", "path": "/$nonce", "value": theirNonce}}))
					}
					h.ServeHTTP(w, r)
				})
			}
		})

	e.expect(e.do("PUT", "/docs/f.md", "one"), 201, "PUT f.md")
	e.expect(e.do("GET", "/docs/f.md", ""), 200, "GET f.md")
	uploads.Store(0)
	arm.Store(true)
	e.expect(e.do("PUT", "/docs/f.md", "three"), 201, "PUT f.md, its head moved after the upload")
	if n := uploads.Load(); n != 1 {
		t.Fatalf("%d uploads", n)
	}
	ref, data := e.rawOf("docs", "f.md")
	if string(data) != "three" || ref["$nonce"] != theirNonce {
		t.Fatalf("f.md %v %q", ref, data)
	}
	if p := patchPaths(t, e.lastEntry("docs", "f.md").Patches); strings.Join(p, " ") != "/$blob /size" {
		t.Fatalf("the save's patch set writes %q", p)
	}

	// Changed and changed back by someone else: a conflict, nothing
	// uploaded.
	e.expect(e.do("GET", "/docs/f.md", ""), 200, "GET f.md")
	h, _ := e.load("docs", "f.md")
	cur := ref["$blob"].(string)
	bid := must(e.c.UploadBlob(e.ctx, "docs", "f.md", "text/markdown", "", []byte("theirs")))
	e.theirs("docs", "f.md", replace("/$blob", bid), replace("/size", 6))
	e.theirs("docs", "f.md", replace("/$blob", cur), replace("/size", 5))
	h, _ = e.load("docs", "f.md")
	uploads.Store(0)
	e.expect(e.do("PUT", "/docs/f.md", "mine"), 409, "PUT over bytes changed and changed back")
	if n := uploads.Load(); n != 0 {
		t.Fatalf("%d uploads for a conflict", n)
	}
	e.expectLive("docs", "f.md", h, "after the conflict")

	r := e.expect(e.do("PUT", "/small/big.md", "123456789"), 413, "PUT over blobSize")
	if !strings.Contains(r.body, "blobSize") || uploads.Load() != 0 {
		t.Fatalf("413 %q after %d uploads", r.body, uploads.Load())
	}
}
