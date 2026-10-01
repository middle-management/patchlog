package server

import (
	"bytes"
	"context"
	"testing"
)

// §G.3, §7.8: a remote branch mirrors the blobs its base's documents
// reference, verified against their ids; they are read through, available
// to the branch's writes, kept when the base becomes unreachable, and
// purged with the base's purges.
func TestRemoteBranchBlobs(t *testing.T) {
	a, b, rt := pair(t, []envOpt{withBlobTuning}, []envOpt{withBlobTuning})
	a.mkNS("main", map[string]any{"read": "public"})
	d1 := []byte("first image")
	bid1 := a.upload("main", "p", "image/png", d1)
	p1 := a.create("main", "p", map[string]any{"img": ref(bid1, "image/png", len(d1), "")})
	// Referenced only by an earlier document: still in the history.
	d2 := []byte("second image")
	bid2 := a.upload("main", "p", "image/png", d2)
	a.appendRev("main", "p", p1, ops(op("replace", "/img", ref(bid2, "image/png", len(d2), ""))))
	d3 := []byte("other resource")
	bid3 := a.upload("main", "q", "text/plain", d3)
	a.create("main", "q", map[string]any{"t": ref(bid3, "text/plain", len(d3), "")})
	at := a.nsHead("main")
	late := []byte("after at")
	lbid := a.upload("main", "q", "text/plain", late)
	a.appendRev("main", "q", a.head("main", "q"), ops(op("add", "/l", ref(lbid, "text/plain", len(late), ""))))

	// Bytes that don't match their id are refused, and nothing is written.
	rt.set(tamper(t, a, "/blob/"+bid2, func(b []byte) []byte { return bytes.ToUpper(b) }), "")
	expectCode(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 502, "remote")
	expect(t, b.get("/ns/rel"), 404)
	rt.set(a.srv.URL, "")
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 201)
	// A becomes unreachable: everything was mirrored up front.
	rt.set("http://127.0.0.1:1", "")
	for bid, want := range map[string][]byte{bid1: d1, bid2: d2} {
		g := b.get(blobPath("rel", "p", bid))
		expect(t, g, 200)
		if !bytes.Equal(g.Body, want) {
			t.Fatalf("blob %s through the remote branch: %q", bid, g.Body)
		}
	}
	expect(t, b.get(blobPath("rel", "q", bid3)), 200)
	expect(t, b.get(blobPath("rel", "q", lbid)), 404) // after at
	expect(t, b.get(blobPath("rel", "p", bid3)), 404) // another resource's
	// Available to the branch's writes, which attach it to its own resource.
	w := b.appendRev("rel", "p", b.head("rel", "p"), ops(op("add", "/old", ref(bid1, "image/png", len(d1), ""))))
	expectCode(t, b.write("PATCH", "rel", "p", w, ops(op("add", "/l", ref(lbid, "text/plain", len(late), "")))), 422, "blob")

	// A's purge, followed: the mirrored blobs go.
	rt.set(a.srv.URL, "")
	expect(t, a.purge("main", "q", a.head("main", "q"), "admin"), 204)
	if err := b.e.SyncRemotes(context.Background()); err != nil {
		t.Fatal(err)
	}
	expect(t, b.get(blobPath("rel", "q", bid3)), 410)
	expect(t, b.get(blobPath("rel", "p", bid1)), 200)
}

// §G.3: a remote branch of a branch mirrors blobs read through from the
// branch's base, at every level.
func TestRemoteBranchBlobsChain(t *testing.T) {
	a, b, _ := pair(t, []envOpt{withBlobTuning}, []envOpt{withBlobTuning})
	a.mkNS("base", map[string]any{"read": "public"})
	d := []byte("base blob")
	bid := a.upload("base", "x", "text/plain", d)
	a.create("base", "x", map[string]any{"b": ref(bid, "text/plain", len(d), "")})
	a.upload("base", "y", "text/plain", d)
	a.create("base", "y", map[string]any{"b": ref(bid, "text/plain", len(d), "")})
	expect(t, a.do(req{method: "POST", path: "/ns/base/branches", ifNoneMatch: "*", author: "admin",
		body: map[string]any{"name": "br", "at": a.nsHead("base"), "patches": []any{}}}), 201)
	// y is written in the branch, which keeps referencing the base's blob;
	// x is read through.
	own := []byte("branch blob")
	obid := a.upload("br", "y", "text/plain", own)
	a.appendRev("br", "y", a.head("br", "y"), ops(op("add", "/o", ref(obid, "text/plain", len(own), ""))))
	at := a.nsHead("br")

	expect(t, b.mkRemote("rel", remoteGenesis("br", at, nil)), 201)
	for _, p := range []string{blobPath("rel", "x", bid), blobPath("rel", "y", bid), blobPath("rel", "y", obid)} {
		expect(t, b.get(p), 200)
	}
	b.appendRev("rel", "x", b.head("rel", "x"), ops(op("add", "/again", ref(bid, "text/plain", len(d), ""))))
}
