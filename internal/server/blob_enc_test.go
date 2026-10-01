package server

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// Blobs of sealed (E2) and end-to-end (E3) namespaces (§7.8, §E.2.2,
// §E.3.1). Like every server test, these run on SQLite and, with
// PATCHLOG_TEST_PG, on Postgres.

func withoutBlobSweep(o *core.Options) { o.BlobSweepInterval = -1 }

// openSealedBlob opens a blob sealed for delivery, requiring kid and pl.
func openSealedBlob(t *testing.T, sealed, key []byte, kid string, pl seal.PL) []byte {
	t.Helper()
	h, data, err := seal.OpenBlob(sealed, key)
	if err != nil {
		t.Fatalf("open sealed blob: %v", err)
	}
	if err := h.Expect(kid, pl); err != nil {
		t.Fatalf("sealed blob header %s, want %s %v", h.Raw, kid, pl)
	}
	return data
}

// §E.2.2: a sealed namespace redirects to the blob sealed under the latest
// epoch it is served under; each epoch's sealing is stored once and served
// unchanged; other epochs are 404 no-store, pruned ones 410.
func TestBlobSealedDelivery(t *testing.T) {
	e := newSealedEnv(t, withoutBlobSweep)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	data := []byte("secret blob " + encMarker)
	nonce := seal.NewNonce()
	r, bid := e.putBlob("s", "a", "text/plain", nonce, data)
	expect(t, r, 201)
	expect(t, e.get(blobPath("s", "a", bid)), 404) // pending
	a1 := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), nonce)})))

	g := e.get(blobPath("s", "a", bid))
	expect(t, g, 302)
	loc := g.H.Get("Location")
	if loc != blobPath("s", "a", bid)+"/e/1" || g.H.Get("Cache-Control") != ccHead || g.H.Get("Cache-Tag") != "ns:s,r:s/a" {
		t.Fatalf("redirect %v", g.H)
	}
	s1 := e.get(loc)
	expect(t, s1, 200)
	if s1.H.Get("Content-Type") != core.SealedBlobType || etagOf(s1) != bid+".1" || s1.H.Get("Cache-Control") != ccImmutable ||
		s1.H.Get("Cache-Tag") != "ns:s,r:s/a" || strings.Contains(string(s1.Body), encMarker) {
		t.Fatalf("sealed blob %v", s1.H)
	}
	keys, _ := e.keysOf("s", nil, "")
	if got := openSealedBlob(t, s1.Body, resKey(t, keys["s#1"], "s", "a"), "s#1", seal.BlobPL("s", "a", bid)); string(got) != string(data) {
		t.Fatalf("opened %q", got)
	}
	// Stored once: the same bytes every time, also to readers racing on a
	// sealing not stored yet (below), and conditional requests.
	if string(e.get(loc).Body) != string(s1.Body) {
		t.Fatal("the sealed bytes changed")
	}
	expect(t, e.do(req{method: "GET", path: loc, hdr: map[string]string{"If-None-Match": quote(bid + ".1")}}), 304)
	rr := e.do(req{method: "GET", path: loc, hdr: map[string]string{"Range": "bytes=0-3"}})
	if rr.Code != 206 || string(rr.Body) != "PLB1" {
		t.Fatalf("range %d %q", rr.Code, rr.Body)
	}
	// Epochs it isn't served under.
	for _, ep := range []string{"2", "0", "01", "x"} {
		g := e.get(blobPath("s", "a", bid) + "/e/" + ep)
		expect(t, g, 404)
		if ep == "2" && g.H.Get("Cache-Control") != "no-store" {
			t.Fatalf("unserved epoch %v", g.H)
		}
	}

	// After a rotation, only a revision written under the new epoch serves
	// the blob under it.
	if ep, err := e.e.RotateEpoch(context.Background(), "s", core.RotateAuthor); err != nil || ep != 2 {
		t.Fatalf("rotate: %d %v", ep, err)
	}
	if g := e.get(blobPath("s", "a", bid)); g.H.Get("Location") != loc {
		t.Fatalf("redirect after rotation %v", g.H)
	}
	expect(t, e.get(blobPath("s", "a", bid)+"/e/2"), 404)
	a2 := e.wr("s", "a", a1, withNonce(ops(op("add", "/c", true))))
	loc2 := blobPath("s", "a", bid) + "/e/2"
	if g := e.get(blobPath("s", "a", bid)); g.H.Get("Location") != loc2 {
		t.Fatalf("redirect %v", g.H)
	}
	var wg sync.WaitGroup
	bodies := make([]string, 6)
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			bodies[i] = string(e.get(loc2).Body)
		}(i)
	}
	wg.Wait()
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatal("concurrent first readers got different sealings")
		}
	}
	keys, _ = e.keysOf("s", nil, "")
	if got := openSealedBlob(t, []byte(bodies[0]), resKey(t, keys["s#2"], "s", "a"), "s#2", seal.BlobPL("s", "a", bid)); string(got) != string(data) {
		t.Fatalf("opened %q", got)
	}
	if string(e.get(loc).Body) != string(s1.Body) {
		t.Fatal("the epoch-1 sealing changed")
	}

	// Pruning every epoch-1 revision: that epoch is 410, the blob stays.
	e.clock.Advance(10 * time.Minute)
	expect(t, e.prune("s", "a", map[string]any{"horizon": a2}, "admin"), 200)
	g = e.get(loc)
	expectCode(t, g, 410, "pruned")
	if g.Str("horizon") != a2 {
		t.Fatalf("pruned epoch %s", g.Body)
	}
	if g := e.get(blobPath("s", "a", bid)); g.H.Get("Location") != loc2 {
		t.Fatalf("redirect after prune %v", g.H)
	}
	expect(t, e.get(loc2), 200)
	// Pruning the last document that references it ends the attachment.
	a3 := e.wr("s", "a", a2, withNonce(ops(op("remove", "/b"))))
	e.clock.Advance(10 * time.Minute)
	expect(t, e.prune("s", "a", map[string]any{"horizon": a3}, "admin"), 200)
	expectCode(t, e.get(blobPath("s", "a", bid)), 410, "pruned")
	expectCode(t, e.get(loc2), 410, "pruned")

	// A purge: every blob of the resource is 410.
	d2 := []byte("purged blob")
	n2 := seal.NewNonce()
	_, b2 := e.putBlob("s", "p", "text/plain", n2, d2)
	p1 := e.wr("s", "p", "", withNonce(addRoot(map[string]any{"b": ref(b2, "text/plain", len(d2), n2)})))
	expect(t, e.get(blobPath("s", "p", b2)+"/e/2"), 200)
	expect(t, e.do(req{method: "POST", path: "/r/s/p/purge", ifMatch: p1, author: "admin"}), 204)
	expect(t, e.get(blobPath("s", "p", b2)), 410)
	expect(t, e.get(blobPath("s", "p", b2)+"/e/2"), 410)
}

// §E.2.2: with pad, the plaintext of a sealed blob is padded with zero
// bytes to its bucket.
func TestBlobSealedPadded(t *testing.T) {
	e := newSealedEnv(t, withoutBlobSweep)
	e.mkNS("p", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed", "pad": true}})
	data := []byte("short")
	nonce := seal.NewNonce()
	_, bid := e.putBlob("p", "a", "text/plain", nonce, data)
	e.wr("p", "a", "", withNonce(addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), nonce)})))
	s := e.get(blobPath("p", "a", bid) + "/e/1")
	expect(t, s, 200)
	h, err := seal.ParseBlobHeader(s.Body)
	if err != nil {
		t.Fatal(err)
	}
	if want := 8 + len(h.Raw) + 12 + seal.PadLen(8+len(data)) + 16; len(s.Body) != want {
		t.Fatalf("sealed length %d, want %d", len(s.Body), want)
	}
	keys, _ := e.keysOf("p", nil, "")
	if got := openSealedBlob(t, s.Body, resKey(t, keys["p#1"], "p", "a"), "p#1", seal.BlobPL("p", "a", bid)); string(got) != string(data) {
		t.Fatalf("opened %q", got)
	}
}

// §E.2.2, §E.2.5: a branch seals read-through blobs under its own keys. A
// request for a blob none of whose referencing revisions has an epoch yet
// fixes the newest of them under the current epoch first.
func TestBlobSealedBranch(t *testing.T) {
	e := newSealedEnv(t, withoutBlobSweep)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	data := []byte("base blob")
	nonce := seal.NewNonce()
	_, bid := e.putBlob("s", "x", "text/plain", nonce, data)
	x1 := e.wr("s", "x", "", withNonce(addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), nonce)})))
	expect(t, e.branch("s", map[string]any{"name": "b"}, "admin"), 201)
	// No revision referencing it has an epoch in the branch yet: the blob
	// request seals x1 under the branch's current epoch first.
	g := e.get(blobPath("b", "x", bid))
	expect(t, g, 302)
	if g.H.Get("Location") != blobPath("b", "x", bid)+"/e/1" {
		t.Fatalf("redirect %v", g.H)
	}
	// The document is then served under that epoch.
	bk, _ := e.keysOf("b", nil, "")
	rv := e.get("/r/b/x/rev/" + x1)
	expect(t, rv, 200)
	open(t, string(rv.Body), resKey(t, bk["b#1"], "b", "x"), "b#1", seal.ResourcePL("b", "x", x1, seal.KindDoc))
	s := e.get(g.H.Get("Location"))
	expect(t, s, 200)
	if got := openSealedBlob(t, s.Body, resKey(t, bk["b#1"], "b", "x"), "b#1", seal.BlobPL("b", "x", bid)); string(got) != string(data) {
		t.Fatalf("opened %q", got)
	}
	// The branch's own write serves it under the branch's epoch too.
	e.wr("b", "x", x1, withNonce(ops(op("add", "/c", 1))))
	expect(t, e.get(blobPath("b", "x", bid)), 302)
}

// sealedOp seals patches for ns/name on parent under k (kid {ns}#1) with a
// declared blob list.
func sealedOp(t *testing.T, k []byte, ns, name, parent string, patches []any, blobs ...string) string {
	t.Helper()
	b, err := seal.SealPatchSet(k, ns+"#1", ns, name, parent, jsonv.FromGo(patches))
	if err != nil {
		t.Fatal(err)
	}
	if b, err = seal.WithBlobs(b, blobs); err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// writeAs sends a raw patch set as author who (parent "" creates; restore
// needs the tombstone as parent).
func (e *tenv) writeAs(ns, name, parent, raw, who string) *resp {
	e.t.Helper()
	q := req{method: "PATCH", path: "/r/" + ns + "/" + name, ifMatch: parent, raw: raw, hasRaw: true, author: who}
	if parent == "" {
		q.ifNoneMatch = "*"
	}
	return e.do(q)
}

// uploadE2E encrypts and uploads data to ns/name and returns the reference.
func (e *tenv) uploadE2E(ns, name string, data []byte, who string) map[string]any {
	e.t.Helper()
	sealed, r, err := plclient.EncryptBlob("image/png", data, false)
	if err != nil {
		e.t.Fatal(err)
	}
	expect(e.t, e.putBlobAs(ns, name, r["$blob"].(string), core.SealedBlobType, "", sealed, who), 201)
	return r
}

// §E.3.1: sealed writes declare the blobs their document references; the
// server checks and attaches them, keeps the list for restores with [],
// and prunes, purges and merges by it.
func TestBlobE2EDeclared(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, withKeyStore(newKeyStore(t)), withEncTuning, withArchive(t, dir), withoutRetentionLoop, withoutBlobSweep)
	e.mkNS("e", e2eDoc(map[string]any{}))
	k := seal.NewKey()
	data := []byte("a picture " + encMarker)
	ref1 := e.uploadE2E("e", "a", data, "alice")
	bid := ref1["$blob"].(string)
	doc := map[string]any{"pic": ref1}

	// Declared lists: ids, distinct, available, sealed, within the limit.
	other := blobID(core.SealedBlobType, "", []byte("never uploaded"))
	expectCode(t, e.writeAs("e", "a", "", sealedOp(t, k, "e", "a", "", addRoot(doc), other), "alice"), 422, "blob")
	expectCode(t, e.writeAs("e", "a", "", sealedOp(t, k, "e", "a", "", addRoot(doc), "nope"), "alice"), 422, "blob")
	expectCode(t, e.writeAs("e", "a", "", sealedOp(t, k, "e", "a", "", addRoot(doc), bid, bid), "alice"), 422, "blob")
	expectCode(t, e.writeAs("e", "a", "", sealedOp(t, k, "e", "a", "", addRoot(doc), bid), "bob"), 422, "blob") // alice's pending blob
	bad := strings.Replace(sealedOp(t, k, "e", "a", "", addRoot(doc)), `"op":"sealed"`, `"blobs":"x","op":"sealed"`, 1)
	expectCode(t, e.writeAs("e", "a", "", bad, "alice"), 422, "invalid")
	r := e.writeAs("e", "a", "", sealedOp(t, k, "e", "a", "", addRoot(doc), bid), "alice")
	expect(t, r, 201)
	a1 := etagOf(r)
	g := e.get(blobPath("e", "a", bid))
	expect(t, g, 200)
	if g.H.Get("Content-Type") != core.SealedBlobType || g.H.Get("Cache-Control") != ccImmutable {
		t.Fatalf("e2e blob %v", g.H)
	}
	b, err := plclient.DecryptBlob(ref1, g.Body)
	if err != nil || string(b.Data) != string(data) || b.Type != "image/png" {
		t.Fatalf("decrypt %v %v", b, err)
	}
	// The list is in the log, part of the hashed patch set.
	lg := e.get("/r/e/a/rev/" + a1 + "/log").Arr()
	if _, list, ok := seal.SealedOp(lg[0].(map[string]any)["patches"]); !ok || len(list) != 1 || list[0] != bid {
		t.Fatalf("logged patch set %v", lg[0])
	}

	// The list counts against blobsPerDocument (§6.6).
	e.mkNS("lim", e2eDoc(map[string]any{"limits": map[string]any{"blobsPerDocument": 1}}))
	r1 := e.uploadE2E("lim", "x", []byte("one"), "alice")
	r2 := e.uploadE2E("lim", "x", []byte("two"), "alice")
	expectCode(t, e.writeAs("lim", "x", "", sealedOp(t, k, "lim", "x", "", addRoot(map[string]any{}), r1["$blob"].(string), r2["$blob"].(string)), "alice"), 422, "limit")

	// Delete, then restore with []: the last live document's list is kept,
	// so a prune at the restore keeps the attachment.
	tomb := e.del("e", "a", a1)
	r = e.writeAs("e", "a", tomb, "[]", "bob")
	expect(t, r, 201)
	a2 := etagOf(r)
	e.clock.Advance(10 * time.Minute)
	snap, err := seal.SealSnapshot(k, "e#1", "e", "a", a2, doc)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, e.prune("e", "a", map[string]any{"horizon": a2, "snapshot": snap}, "admin"), 200)
	expect(t, e.get(blobPath("e", "a", bid)), 200)

	// A revision that declares nothing, then a prune whose snapshot declares
	// nothing either: the attachment ends (the archive has the blob).
	r = e.writeAs("e", "a", a2, sealedOp(t, k, "e", "a", a2, ops(op("remove", "/pic"))), "alice")
	expect(t, r, 201)
	a3 := etagOf(r)
	e.clock.Advance(10 * time.Minute)
	snap3, _ := seal.SealSnapshot(k, "e#1", "e", "a", a3, map[string]any{})
	// The snapshot needs no list (§8.6): the server keeps a3's, which is
	// empty.
	expect(t, e.prune("e", "a", map[string]any{"horizon": a3, "snapshot": snap3}, "admin"), 200)
	expectCode(t, e.get(blobPath("e", "a", bid)), 410, "pruned")

	// §F.8.1: a merge from a branch re-seals the patch set for the base with
	// the same list, and the branch's blobs are available through the
	// batch's source: nothing is uploaded to the base.
	ref2 := e.uploadE2E("e", "m", []byte("base"), "alice")
	r = e.writeAs("e", "m", "", sealedOp(t, k, "e", "m", "", addRoot(map[string]any{"p": ref2}), ref2["$blob"].(string)), "alice")
	expect(t, r, 201)
	m1 := etagOf(r)
	expect(t, e.branch("e", map[string]any{"name": "eb"}, "admin"), 201)
	ref3 := e.uploadE2E("eb", "m", []byte("from the branch"), "bob")
	both := []string{ref2["$blob"].(string), ref3["$blob"].(string)}
	patches := ops(op("add", "/q", ref3))
	// In the branch, the base's blob is available through the base.
	expect(t, e.writeAs("eb", "m", m1, sealedOp(t, k, "eb", "m", m1, patches, both...), "bob"), 201)
	item := func() map[string]any {
		return map[string]any{"resource": "m", "ifMatch": m1, "steps": []any{jsonv.MustParse([]byte(sealedOp(t, k, "e", "m", m1, patches, both...)))}}
	}
	expectCode(t, e.batchReq("e", map[string]any{"items": []any{item()}}, "merger"), 422, "batch")
	expect(t, e.batchReq("e", map[string]any{"items": []any{item()}, "source": map[string]any{"ns": "eb", "at": e.nsHead("eb")}}, "merger"), 201)
	expect(t, e.get(blobPath("e", "m", ref3["$blob"].(string))), 200)

	// Purge ends every attachment.
	expect(t, e.do(req{method: "POST", path: "/r/e/m/purge", ifMatch: e.head("e", "m"), author: "admin"}), 204)
	expect(t, e.get(blobPath("e", "m", ref2["$blob"].(string))), 410)
}
