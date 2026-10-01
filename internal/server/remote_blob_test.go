package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
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

// §G.5.2, §E.2.2: a remote branch of a sealed base fetches each blob
// through the base's 302 to an epoch, opens it with the endpoint's keys
// and verifies it against the reference; the branch keeps the plaintext
// encrypted at rest and serves it sealed under its own keys, also once the
// base is unreachable.
func TestRemoteBranchSealedBlobs(t *testing.T) {
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := a.grant(kA, "user:root", []string{"s"}, allVerbs)
	data := []byte("sealed picture " + encMarker)
	nonce := seal.NewNonce()
	r, bid := a.putBlob("s", "x", "image/png", nonce, data, root)
	expect(t, r, 201)
	x1 := a.wr("s", "x", "", withNonce(addRoot(map[string]any{"img": ref(bid, "image/png", len(data), nonce)})), root)
	at := a.nsHead("s", root)
	expect(t, a.get(blobPath("s", "x", bid), root), 302)

	bJWK, bPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	id := bPriv
	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"s"}, []string{"read", "export"}, map[string]any{"enc": bJWK})}
	path := filepath.Join(t.TempDir(), "b.db")
	b := newEnv(t, withOrigin(originB), withRemote(rt, withRemoteIdentity(&mu, &id)), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning, withPath(path))
	sealedBranch := map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}}

	// A sealing that doesn't open is refused, and nothing is written.
	rt.set(tamper(t, a, "/blob/"+bid+"/e/", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }), rt.bearer)
	expectCode(t, b.mkRemote("rel", remoteGenesis("s", at, sealedBranch)), 502, "remote")
	expect(t, b.get("/ns/rel"), 404)
	rt.set(a.srv.URL, rt.bearer)
	expect(t, b.mkRemote("rel", remoteGenesis("s", at, sealedBranch)), 201)
	assertNoPlaintext(t, path)

	// Served sealed under the branch's keys, once a revision referencing it
	// is served (§E.2.2), with A unreachable: it was mirrored up front.
	rt.set("http://127.0.0.1:1", "")
	expect(t, b.get("/r/rel/x/rev/"+x1), 200)
	g := b.get(blobPath("rel", "x", bid))
	expect(t, g, 302)
	s := b.get(g.H.Get("Location"))
	expect(t, s, 200)
	if s.H.Get("Content-Type") != core.SealedBlobType || strings.Contains(string(s.Body), encMarker) {
		t.Fatalf("branch blob %v", s.H)
	}
	keys, _ := b.keysOf("rel", nil, "")
	if got := openSealedBlob(t, s.Body, resKey(t, keys["rel#1"], "rel", "x"), "rel#1", seal.BlobPL("rel", "x", bid)); !bytes.Equal(got, data) {
		t.Fatalf("opened %q", got)
	}
	// Available to the branch's writes.
	b.wr("rel", "x", x1, withNonce(ops(op("add", "/again", ref(bid, "image/png", len(data), nonce)))))
	assertNoPlaintext(t, path)
}

// §G.5.2, §E.3.1: a remote branch of an e2e base mirrors the blobs the
// sealed ops declare (a restore with [] keeps the last live list), the
// writers' ciphertext verbatim, verified against the ids; they are served
// as uploaded and available to the branch's sealed writes.
func TestRemoteBranchE2EBlobs(t *testing.T) {
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("e", e2eDoc(map[string]any{"keys": []any{kA.entry("*")}}))
	adminG := a.grant(kA, "user:admin", []string{"e"}, allVerbs)
	_, readerPriv, _ := seal.GenerateRecipient()
	k := seal.NewKey()
	kr, _ := seal.BuildKeyring("e", 1, k, []*ecdh.PublicKey{readerPriv.PublicKey()})
	a.create("e", "keyring", kr.Value(), adminG)
	upload := func(name, text string) ([]byte, string) {
		sealedBytes, r, err := plclient.EncryptBlob("image/png", []byte(text+" "+encMarker), false)
		if err != nil {
			t.Fatal(err)
		}
		bid := r["$blob"].(string)
		expect(t, a.putBlobAs("e", name, bid, core.SealedBlobType, "", sealedBytes, adminG), 201)
		return sealedBytes, bid
	}
	s1, b1 := upload("d", "one")
	s2, b2 := upload("d", "two")
	d0 := etagOf(a.writeRaw("e", "d", "", sealedOp(t, k, "e", "d", "", addRoot(map[string]any{"n": 0.0}), b1), adminG))
	d1 := etagOf(a.writeRaw("e", "d", d0, sealedOp(t, k, "e", "d", d0, ops(op("add", "/m", 1.0)), b1, b2), adminG))
	tomb := a.del("e", "d", d1, adminG)
	r := a.writeRaw("e", "d", tomb, "[]", adminG)
	expect(t, r, 201)
	d2 := etagOf(r)
	at := a.nsHead("e", adminG)
	_, late := upload("d", "late")
	a.writeRaw("e", "d", d2, sealedOp(t, k, "e", "d", d2, ops(op("add", "/l", 1.0)), b1, b2, late), adminG)

	var bPriv ed25519.PrivateKey
	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"e"}, []string{"read"})}
	path := filepath.Join(t.TempDir(), "b.db")
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning, withPath(path))
	b.opPriv = bPriv
	kB := newKey("badmin")
	genesis := remoteGenesis("e", at, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))

	// Bytes that don't match their id are refused, and nothing is written.
	rt.set(tamper(t, a, "/blob/"+b2, func(b []byte) []byte { b[len(b)-1] ^= 1; return b }), rt.bearer)
	expectCode(t, b.mkRemote("rel", genesis), 502, "remote")
	rt.set(a.srv.URL, rt.bearer)
	expect(t, b.mkRemote("rel", genesis), 201)
	bAdmin := b.grant(kB, "user:b", []string{"rel"}, allVerbs)

	// A unreachable: everything was mirrored up front.
	rt.set("http://127.0.0.1:1", "")
	for bid, want := range map[string][]byte{b1: s1, b2: s2} {
		g := b.get(blobPath("rel", "d", bid), bAdmin)
		expect(t, g, 200)
		if !bytes.Equal(g.Body, want) || g.H.Get("Content-Type") != core.SealedBlobType {
			t.Fatalf("blob %s through the remote branch: %v", bid, g.H)
		}
	}
	expect(t, b.get(blobPath("rel", "d", late), bAdmin), 404) // after at
	// Available to the branch's sealed writes; the late one isn't.
	kb := seal.NewKey()
	expectCode(t, b.writeRaw("rel", "d", d2, sealedOp(t, kb, "rel", "d", d2, ops(op("add", "/x", 1.0)), b2, late), bAdmin), 422, "blob")
	expect(t, b.writeRaw("rel", "d", d2, sealedOp(t, kb, "rel", "d", d2, ops(op("add", "/x", 1.0)), b1, b2), bAdmin), 201)
	assertNoPlaintext(t, path)
}
