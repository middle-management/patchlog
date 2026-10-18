package server

import (
	"crypto/ecdh"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// §7.8: at a raw document's root, the members validation leaves out
// ($schema, a fresh $nonce, a well-formed $successor) aren't part of the
// blob reference; any other member, a $nonce or $successor of another form
// included, is 422 blob, and nested references allow none.
func TestBlobRefRootMembers(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("schemas", map[string]any{"read": "public"})
	e.mkNS("m", map[string]any{"read": "public"})
	file := e.create("schemas", "file", map[string]any{"$schema": dialect, "type": "object", "required": []any{"$blob"}})
	data := []byte("# a file\n")
	bid := e.upload("m", "f", "text/markdown", data)
	nonce := "abcdefghijklmnopqrstuvwxyz"
	root := func(extra map[string]any) map[string]any {
		m := ref(bid, "text/markdown", len(data), "")
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	head := e.create("m", "f", root(map[string]any{"$schema": "/r/schemas/file/rev/" + file, "$nonce": nonce}))
	head = e.appendRev("m", "f", head, ops(op("replace", "/$nonce", "zyxwvutsrqponmlkjihgfedcba"), op("add", "/$successor", "/r/other/f")))
	for _, bad := range []map[string]any{
		{"$nonce": "short"},
		{"$successor": "Bad"},
		{"$successor": 1.0},
		{"title": "x"},
	} {
		r := e.write("PATCH", "m", "g", "", addRoot(root(bad)))
		expectCode(t, r, 422, "blob")
	}
	nested := map[string]any{"img": root(map[string]any{"$nonce": nonce})}
	expectCode(t, e.write("PATCH", "m", "g", "", addRoot(nested)), 422, "blob")
	nested = map[string]any{"img": root(map[string]any{"$successor": "x"})}
	expectCode(t, e.write("PATCH", "m", "g", "", addRoot(nested)), 422, "blob")
	// A namespace requiring nonces holds raw documents (§C.7).
	e.mkNS("req", map[string]any{"read": "public", "nonce": "required"})
	rb := e.upload("req", "f", "text/markdown", data)
	if rb != bid {
		t.Fatal("blob id")
	}
	e.create("req", "f", root(map[string]any{"$nonce": nonce}))
	_ = head
}

// rawGet reads path (a …/raw URL) and checks the 302 to ns/name's blob
// bid, cached with class, HEAD alike.
func (e *tenv) rawRedirect(path, ns, name, bid, etag, class string, bearer ...string) {
	e.t.Helper()
	for _, method := range []string{"GET", "HEAD"} {
		q := req{method: method, path: path}
		if len(bearer) > 0 {
			q.bearer = bearer[0]
		}
		r := e.do(q)
		if r.Code != 302 || r.H.Get("Location") != blobPath(ns, name, bid) || r.H.Get("ETag") != quote(etag) ||
			r.H.Get("Cache-Tag") != "ns:"+ns+",r:"+ns+"/"+name || class != "" && r.H.Get("Cache-Control") != class {
			e.t.Fatalf("%s %s: %d %v %s", method, path, r.Code, r.H, r.Body)
		}
	}
}

// §7.1, §7.8: …/raw and …/rev/{id}/raw redirect to the blob a raw document
// stands for, cached as the document URL (head pointer, immutable) with
// its tags; a document that isn't raw is 404 not_found, cached likewise.
// Every other answer is the document URL's: unknown (short), a tombstoned
// head (with successor), a tombstone id, a prune, a purge. A branch's
// Location is its own, which reads its base's blob through. Blob
// responses carry nosniff and the sandbox policy (§7.8 Reading).
func TestRaw(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("schemas", map[string]any{"read": "public"})
	e.mkNS("m", map[string]any{"read": "public"})
	file := e.create("schemas", "file", map[string]any{"$schema": dialect, "type": "object", "required": []any{"$blob", "type"}})
	md := []byte("# Notes\n\n<script>alert(1)</script>\n")
	bid := e.upload("m", "notes", "text/markdown", md)
	nonce := "abcdefghijklmnopqrstuvwxyz"
	r0 := e.create("m", "notes", map[string]any{"$blob": bid, "type": "text/markdown", "size": len(md), "$schema": "/r/schemas/file/rev/" + file, "$nonce": nonce})
	e.rawRedirect("/r/m/notes/raw", "m", "notes", bid, r0, ccHead)
	e.rawRedirect("/r/m/notes/rev/"+r0+"/raw", "m", "notes", bid, r0, ccImmutable)
	if r := e.get("/r/m/notes/rev/" + r0 + "/raw"); r.H.Get("X-Revision") != r0 {
		t.Fatalf("X-Revision %v", r.H)
	}
	b := e.get(blobPath("m", "notes", bid))
	expect(t, b, 200)
	if string(b.Body) != string(md) || b.H.Get("Content-Type") != "text/markdown" || b.H.Get("X-Content-Type-Options") != "nosniff" || b.H.Get("Content-Security-Policy") != "sandbox" {
		t.Fatalf("blob %v", b.H)
	}

	// No longer raw: a member beyond those validation leaves out.
	r1 := e.appendRev("m", "notes", r0, ops(op("replace", "/$nonce", "zyxwvutsrqponmlkjihgfedcba"), op("add", "/$successor", "/r/m/elsewhere")))
	e.rawRedirect("/r/m/notes/raw", "m", "notes", bid, r1, ccHead)
	if e.upload("m", "plain", "text/markdown", md) != bid {
		t.Fatal("blob id")
	}
	e.create("m", "plain", map[string]any{"title": "x", "file": map[string]any{"$blob": bid, "type": "text/markdown", "size": len(md)}})
	for path, class := range map[string]string{"/r/m/plain/raw": ccHead, "/r/m/plain/rev/" + e.head("m", "plain") + "/raw": ccImmutable} {
		r := e.get(path)
		expectCode(t, r, 404, "not_found")
		if r.H.Get("Cache-Control") != class || r.H.Get("Cache-Tag") != "ns:m,r:m/plain" {
			t.Fatalf("%s: %v", path, r.H)
		}
	}
	expectCode(t, e.get("/r/schemas/file/raw"), 404, "not_found")
	// Unknown: as the document URLs, short.
	for _, path := range []string{"/r/m/none/raw", "/r/m/notes/rev/" + hashID(t, "", []byte("x")) + "/raw", "/r/m/notes/rev/nope/raw", "/r/none/x/raw"} {
		r := e.get(path)
		expect(t, r, 404)
		if path != "/r/none/x/raw" && r.H.Get("Cache-Control") != ccShort {
			t.Fatalf("%s: %v", path, r.H)
		}
	}
	expectCode(t, e.get("/r/m/notes/raw?x=1"), 400, "bad_input")

	// A branch reads it through, under its own URLs.
	expect(t, e.branch("m", map[string]any{"name": "br", "at": e.nsHead("m"), "patches": []any{}}, "alice"), 201)
	e.rawRedirect("/r/br/notes/raw", "br", "notes", bid, r1, ccHead)
	if b := e.get(blobPath("br", "notes", bid)); b.Code != 200 || string(b.Body) != string(md) {
		t.Fatalf("branch blob %d", b.Code)
	}

	// Moved: the tombstoned head's 410, with successor; the tombstone id's
	// immutable 410; the last revision still redirects.
	tomb := e.del("m", "notes", r1)
	r := e.get("/r/m/notes/raw")
	expectCode(t, r, 410, "gone")
	if r.Obj()["tombstone"] != tomb || r.Obj()["last"] != r1 || r.Obj()["successor"] != "/r/m/elsewhere" || r.H.Get("ETag") != quote(tomb) || r.H.Get("Cache-Control") != ccHead {
		t.Fatalf("tombstoned raw %v %s", r.H, r.Body)
	}
	if h := e.do(req{method: "HEAD", path: "/r/m/notes/raw"}); h.Code != 410 || len(h.Body) != 0 {
		t.Fatalf("HEAD tombstoned %d", h.Code)
	}
	r = e.get("/r/m/notes/rev/" + tomb + "/raw")
	expectCode(t, r, 410, "gone")
	if r.H.Get("Cache-Control") != ccImmutable {
		t.Fatalf("tombstone id %v", r.H)
	}
	e.rawRedirect("/r/m/notes/rev/"+r1+"/raw", "m", "notes", bid, r1, ccImmutable)

	// Pruned below a horizon: 410 pruned.
	pb := e.upload("m", "p", "image/png", []byte("png0"))
	p0 := e.create("m", "p", map[string]any{"$blob": pb, "type": "image/png", "size": 4})
	pb1 := e.upload("m", "p", "image/png", []byte("png1"))
	e.clock.Advance(10 * time.Minute)
	p1 := e.appendRev("m", "p", p0, ops(op("replace", "/$blob", pb1)))
	e.clock.Advance(10 * time.Minute)
	p2 := e.appendRev("m", "p", p1, ops(op("add", "/$nonce", nonce)))
	expect(t, e.prune("m", "p", map[string]any{"horizon": p2}, "admin"), 200)
	r = e.get("/r/m/p/rev/" + p0 + "/raw")
	expectCode(t, r, 410, "pruned")
	if r.H.Get("Cache-Control") != ccPruned || r.Obj()["horizon"] != p2 {
		t.Fatalf("pruned %v %s", r.H, r.Body)
	}
	e.rawRedirect("/r/m/p/raw", "m", "p", pb1, p2, ccHead)

	// Purged: 410, long, at both URLs.
	expect(t, e.purge("m", "p", p2, "admin"), 204)
	for _, path := range []string{"/r/m/p/raw", "/r/m/p/rev/" + p2 + "/raw"} {
		r := e.get(path)
		expectCode(t, r, 410, "gone")
		if r.H.Get("Cache-Control") != ccLong {
			t.Fatalf("%s: %v", path, r.H)
		}
	}
}

// §7.1: not offered in sealed or e2e namespaces, the e2e keyring included:
// 404 not_offered after the read check, cached as the document URL; a
// purged namespace's 410 comes first (§8.5). A per-resource reader gets
// the ordinary 404 for another resource.
func TestRawNotOffered(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t, withBlobTuning)
	k := newKey("admin")
	e.mkNS("s", sealedDoc(map[string]any{"keys": []any{k.entry("*")}}))
	e.mkNS("p", map[string]any{"keys": []any{k.entry("*")}})
	admin := e.grant(k, "user:root", []string{"s", "p"}, allVerbs)
	one := e.grant(k, "user:r", []string{"s", "p"}, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	nonce := "abcdefghijklmnopqrstuvwxyz"
	data := []byte("bytes")
	var heads = map[string]string{}
	for _, ns := range []string{"s", "p"} {
		r, bid := e.putBlob(ns, "a", "application/octet-stream", nonce, data, admin)
		expect(t, r, 201)
		heads[ns] = e.wr(ns, "a", "", withNonce(addRoot(map[string]any{"$blob": bid, "type": "application/octet-stream", "size": len(data), "nonce": nonce})), admin)
	}
	expectCode(t, e.get("/r/s/a/raw"), 401, "unauthenticated")
	expectCode(t, e.get("/r/p/b/raw", one), 404, "not_found")
	// Sealed namespaces use the public classes (§9).
	for path, class := range map[string]string{"/r/s/a/raw": ccHead, "/r/s/a/rev/" + heads["s"] + "/raw": ccImmutable} {
		r := e.get(path, one)
		expectCode(t, r, 404, "not_offered")
		if r.H.Get("Cache-Control") != class || r.H.Get("Cache-Tag") != "ns:s,r:s/a" {
			t.Fatalf("%s: %v", path, r.H)
		}
	}
	if r := e.get("/r/p/a/raw", one); r.Code != 302 || r.H.Get("Cache-Control") != "private, max-age=0" {
		t.Fatalf("private raw %d %v", r.Code, r.H)
	}
	sh := e.purgeNSAs("s", admin)
	expectPurged(t, e.get("/r/s/a/raw", one), sh)
	expectPurged(t, e.get("/r/s/a/rev/"+heads["s"]+"/raw", one), sh)

	// e2e: content and keyring alike.
	f := newE2E(t)
	readerPub, _ := seal.ParseRecipientJWK(f.readerJWK)
	kr, err := seal.BuildKeyring("e", 1, seal.NewKey(), []*ecdh.PublicKey{readerPub})
	if err != nil {
		t.Fatal(err)
	}
	krID := f.create("e", core.KeyringName, kr.Value(), f.adminG)
	expectCode(t, f.get("/r/e/"+core.KeyringName+"/raw", f.readerG), 404, "not_offered")
	expectCode(t, f.get("/r/e/"+core.KeyringName+"/rev/"+krID+"/raw", f.readerG), 404, "not_offered")
	expectCode(t, f.get("/r/e/none/raw", f.readerG), 404, "not_offered")
	expectCode(t, f.get("/r/e/none/raw"), 401, "unauthenticated")
}

// §7.8 Reading: every blob response carries nosniff and the sandbox
// policy: 200, 206, 304, errors, and a sealed namespace's 302 and epoch
// blobs.
func TestBlobHeaders(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t, withBlobTuning)
	e.mkNS("m", map[string]any{"read": "public"})
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	html := []byte("<html><script>alert(document.cookie)</script></html>")
	bid := e.upload("m", "a", "text/html", html)
	e.create("m", "a", map[string]any{"page": ref(bid, "text/html", len(html), "")})
	nonce := "abcdefghijklmnopqrstuvwxyz"
	r, sbid := e.putBlob("s", "a", "text/html", nonce, html)
	expect(t, r, 201)
	e.wr("s", "a", "", withNonce(addRoot(map[string]any{"page": ref(sbid, "text/html", len(html), nonce)})))
	check := func(r *resp, code int) {
		t.Helper()
		if r.Code != code || r.H.Get("X-Content-Type-Options") != "nosniff" || r.H.Get("Content-Security-Policy") != "sandbox" {
			t.Fatalf("%d (want %d) %v", r.Code, code, r.H)
		}
	}
	p := blobPath("m", "a", bid)
	check(e.get(p), 200)
	check(e.do(req{method: "HEAD", path: p}), 200)
	check(e.do(req{method: "GET", path: p, hdr: map[string]string{"Range": "bytes=0-3"}}), 206)
	check(e.do(req{method: "GET", path: p, hdr: map[string]string{"If-None-Match": quote(bid)}}), 304)
	check(e.get(blobPath("m", "a", blobID("text/plain", "", []byte("none")))), 404)
	check(e.get(blobPath("m", "zz", bid)), 404)
	s := e.get(blobPath("s", "a", sbid))
	check(s, 302)
	check(e.get(s.H.Get("Location")), 200)
	check(e.do(req{method: "GET", path: s.H.Get("Location"), hdr: map[string]string{"Range": "bytes=0-9"}}), 206)
	check(e.get(blobPath("s", "a", sbid)+"/e/99"), 404)
}
