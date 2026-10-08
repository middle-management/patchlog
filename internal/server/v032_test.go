package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
)

// Behaviour new in v0.32.

// §7.8: a purged namespace is 410 after authorisation, like a purged
// resource.
func TestBlobUploadPurgedNamespaceAfterAuth(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil, withBlobTuning)
	e := f.tenv
	k := newKey("gone-admin")
	e.mkNS("gone", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	admin := e.grant(k, "user:root", []string{"gone"}, allVerbs)
	reader := e.grant(k, "user:r", []string{"gone"}, []string{"read"})
	expect(t, e.patchNS("gone", ops(op("add", "/frozen", true)), admin), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/gone/purge", ifMatch: e.nsHead("gone", admin), bearer: admin}), 204)
	data := []byte("late")
	bid := blobID("text/plain", "", data)
	expectCode(t, e.putBlobAs("gone", "a", bid, "text/plain", "", data), 401, "unauthenticated")
	expectCode(t, e.putBlobAs("gone", "a", bid, "text/plain", "", data, reader), 403, "forbidden")
	expectCode(t, e.putBlobAs("gone", "a", bid, "text/plain", "", data, admin), 410, "gone")
}

// §7.8 Copying: a request with a body, or a Blob-From that can't be
// parsed, is 400 before anything else of the copy; a different bid is 422
// before the source is looked at (404).
func TestBlobCopyOrder(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("c", map[string]any{})
	data := []byte("copy me")
	bid := e.upload("c", "src", "text/plain", data)
	e.create("c", "src", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	other := blobID("text/plain", "", []byte("other"))
	withBody := func(from, id string) *resp {
		q := req{method: "PUT", path: blobPath("c", "dst", id), raw: "x", hasRaw: true, ct: "text/plain", hdr: map[string]string{"Blob-From": from}, author: "alice"}
		return e.do(q)
	}
	// A body: 400, even with another bid and an unknown source.
	expectCode(t, withBody(blobPath("c", "nowhere", other), bid), 400, "bad_input")
	// An unparseable Blob-From: 400, even with another bid.
	expectCode(t, e.copyBlob("c", "dst", other, "/not/a/blob/url", ""), 400, "bad_input")
	// Another bid: 422, even though the source doesn't exist.
	expectCode(t, e.copyBlob("c", "dst", other, blobPath("c", "nowhere", bid), ""), 422, "blob")
	// Then the source: 404.
	expectCode(t, e.copyBlob("c", "dst", bid, blobPath("c", "nowhere", bid), ""), 404, "not_found")
	expect(t, e.copyBlob("c", "dst", bid, blobPath("c", "src", bid), ""), 201)
}

// §7.8 Pending: a write whose document references a blob ends every
// pending entry for it in that resource, whoever uploaded it, also when
// the blob is attached already.
func TestBlobWriteEndsEveryPendingEntry(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("p", map[string]any{})
	data := []byte("shared")
	bid := e.upload("p", "a", "text/plain", data, "alice")
	h := e.create("p", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")}, "alice")
	// Bob uploads the attached blob again: a pending entry of his own.
	expect(t, e.putBlobAs("p", "a", bid, "text/plain", "", data, "bob"), 201)
	expect(t, e.putBlobAs("p", "b", bid, "text/plain", "", data, "bob"), 201)
	if s := e.blobStats(); s.Pending != 2 {
		t.Fatalf("stats %+v", s)
	}
	// Alice's next write still references it: bob's entry in a ends; his
	// entry in b, another resource, stays.
	e.appendRev("p", "a", h, ops(op("add", "/n", 1)), "alice")
	if s := e.blobStats(); s.Pending != 1 || s.Attached != 1 {
		t.Fatalf("stats %+v", s)
	}
}

// §7.5: a batch's local source.at is checked, with code "source", only for
// a caller with unrestricted read on source.ns (with Source-Authorization
// if given); for anyone else the source is recorded unchecked and makes no
// blobs available. An origin equal to this deployment's own is 422.
func TestBatchSourceChecked(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil, withBlobTuning)
	e := f.tenv
	k2 := newKey("k2")
	e.mkNS("other", map[string]any{"read": "grant", "keys": []any{k2.entry("read", "create", "append")}})
	og := e.grant(k2, "user:o", []string{"other"}, []string{"read", "create", "append"})
	onlyA := e.grant(k2, "user:o", []string{"other"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	data := []byte("in other")
	bid := e.upload("other", "a", "text/plain", data, og)
	e.create("other", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")}, og)
	at := e.nsHead("other", og)
	bogus := e.nsHead("sec", f.issuerG) // not in other's chain

	plain := func(name string) map[string]any {
		return map[string]any{"resource": name, "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"n": 1})}}
	}
	withBlob := func(name string) map[string]any {
		return map[string]any{"resource": name, "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")})}}
	}
	batch := func(item map[string]any, source map[string]any, srcGrant string) *resp {
		q := req{method: "POST", path: "/ns/sec/batch", bearer: f.issuerG, body: map[string]any{"items": []any{item}, "source": source}}
		if srcGrant != "" {
			q.hdr = map[string]string{"Source-Authorization": "Bearer " + srcGrant}
		}
		return e.do(q)
	}
	// The issuer can't read other: a bad source.at is recorded unchecked.
	r := batch(plain("x1"), map[string]any{"ns": "other", "at": bogus}, "")
	expect(t, r, 201)
	lg := e.get("/ns/sec/rev/"+e.nsHead("sec", f.issuerG)+"/log", f.issuerG).Arr()
	if src, _ := lg[len(lg)-1].(map[string]any)["source"].(map[string]any); src["at"] != bogus {
		t.Fatalf("recorded source %v", lg[len(lg)-1])
	}
	// ... and makes no blobs available, even with a good source.at.
	expectCode(t, batch(withBlob("a"), map[string]any{"ns": "other", "at": at}, ""), 422, "batch")
	// A per-resource reader of the source: unchecked too, and no blobs.
	expect(t, batch(plain("x3"), map[string]any{"ns": "other", "at": bogus}, onlyA), 201)
	expectCode(t, batch(withBlob("a"), map[string]any{"ns": "other", "at": at}, onlyA), 422, "batch")
	// With unrestricted read: checked (422 source), and the blobs are
	// available through a good one.
	expectCode(t, batch(plain("x5"), map[string]any{"ns": "other", "at": bogus}, og), 422, "source")
	expect(t, batch(withBlob("a"), map[string]any{"ns": "other", "at": at}, og), 201)
	// An origin equal to this deployment's own.
	expectCode(t, batch(plain("x7"), map[string]any{"origin": "https://cms.example", "ns": "other", "at": at}, ""), 422, "invalid")
}

// §7.8 Availability: through a batch's source, a blob attached in a base
// the source reads through counts, as the source sees it at source.at.
func TestBatchSourceReadThrough(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("main", map[string]any{})
	data := []byte("in the base")
	bid := e.upload("main", "a", "text/plain", data)
	e.create("main", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	expect(t, e.branch("main", map[string]any{"name": "feat"}, "admin"), 201)
	at := e.nsHead("feat")
	e.mkNS("elsewhere", map[string]any{})
	item := map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")})}}
	expectCode(t, e.batchReq("elsewhere", map[string]any{"items": []any{item}}, "alice"), 422, "batch")
	expect(t, e.batchReq("elsewhere", map[string]any{"items": []any{item}, "source": map[string]any{"ns": "feat", "at": at}}, "alice"), 201)
	expect(t, e.get(blobPath("elsewhere", "a", bid)), 200)
}

// §7.5 Dry run: a blob that isn't available is reported, and the later
// steps run as if it were: the report has the ids, or a later step's
// failure with the blob failure alongside.
func TestBlobDryRunCarriesOn(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("d", map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/doc/forbidden", "value": nil}}})
	missing := blobID("text/plain", "", []byte("missing"))
	mref := ref(missing, "text/plain", 7, "")
	body := map[string]any{"items": []any{
		map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"b": mref, "forbidden": nil})}},
		map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"b": mref, "forbidden": true})}},
	}}
	r := e.do(req{method: "POST", path: "/ns/d/batch?dry-run=1", author: "alice", body: body})
	expect(t, r, 200)
	items := r.Obj()["items"].([]any)
	a, b := items[0].(map[string]any), items[1].(map[string]any)
	if a["status"] != 422.0 || a["code"] != "blob" {
		t.Fatalf("a: %v", a)
	}
	if ids, _ := a["ids"].([]any); len(ids) != 1 {
		t.Fatalf("a's ids: %v", a)
	}
	if b["status"] == 200.0 || b["code"] == "blob" || b["blob"] == nil {
		t.Fatalf("b: %v", b)
	}
	// A submit stops at the blob.
	r = e.do(req{method: "POST", path: "/ns/d/batch", author: "alice", body: body})
	expectCode(t, r, 422, "batch")
}

// §E.2.2, §E.2.5: a revision written before its namespace became sealed
// has no epoch until it is first served: a request for a blob it
// references fixes it under the current epoch first.
func TestBlobSealedFixesEpoch(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t, withoutBlobSweep)
	e.mkNS("s", map[string]any{"read": "public"})
	data := []byte("before sealing")
	nonce := seal.NewNonce()
	_, bid := e.putBlob("s", "a", "text/plain", nonce, data)
	a1 := e.wr("s", "a", "", addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), nonce)}))
	expect(t, e.patchNS("s", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	if ep, err := e.e.RotateEpoch(context.Background(), "s", core.RotateAuthor); err != nil || ep != 2 {
		t.Fatalf("rotate: %d %v", ep, err)
	}
	g := e.get(blobPath("s", "a", bid))
	expect(t, g, 302)
	if g.H.Get("Location") != blobPath("s", "a", bid)+"/e/2" {
		t.Fatalf("redirect %v", g.H)
	}
	// The revision keeps that epoch, even after another rotation.
	if _, err := e.e.RotateEpoch(context.Background(), "s", core.RotateAuthor); err != nil {
		t.Fatal(err)
	}
	keys, _ := e.keysOf("s", nil, "")
	rv := e.get("/r/s/a/rev/" + a1)
	expect(t, rv, 200)
	open(t, string(rv.Body), resKey(t, keys["s#2"], "s", "a"), "s#2", seal.ResourcePL("s", "a", a1, seal.KindDoc))
	// Its log entry too, first sealed after the rotation.
	lg := e.get("/r/s/a/rev/" + a1 + "/log").Arr()
	if len(lg) != 1 {
		t.Fatalf("log %v", lg)
	}
	open(t, lg[0].(string), resKey(t, keys["s#2"], "s", "a"), "s#2", seal.ResourcePL("s", "a", a1, seal.KindRev))
	s := e.get(blobPath("s", "a", bid) + "/e/2")
	expect(t, s, 200)
	if got := openSealedBlob(t, s.Body, resKey(t, keys["s#2"], "s", "a"), "s#2", seal.BlobPL("s", "a", bid)); string(got) != string(data) {
		t.Fatalf("opened %q", got)
	}
	expect(t, e.get(blobPath("s", "a", bid)+"/e/3"), 404)
}

// D.4, §E.2.2: restoring an archive clears the recorded 410 epochs, whose
// revisions are served again.
func TestBlobSealedRestoreClearsPrunedEpochs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	e := newSealedEnv(t, withoutBlobSweep, withArchive(t, dir), withoutRetentionLoop, func(o *core.Options) {
		if !pgtest.Enabled() {
			// Restoring an archive encrypted at rest opens it with the
			// resource's data key in a read of its own, while the restore
			// holds the write transaction: :memory: has one connection.
			o.Path = filepath.Join(t.TempDir(), "db.sqlite")
		}
	})
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	data := []byte("kept across epochs")
	nonce := seal.NewNonce()
	_, bid := e.putBlob("s", "a", "text/plain", nonce, data)
	a1 := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), nonce)})))
	loc1 := blobPath("s", "a", bid) + "/e/1"
	expect(t, e.get(loc1), 200)
	if _, err := e.e.RotateEpoch(context.Background(), "s", core.RotateAuthor); err != nil {
		t.Fatal(err)
	}
	a2 := e.wr("s", "a", a1, withNonce(ops(op("add", "/c", 1))))
	e.clock.Advance(10 * time.Minute)
	expect(t, e.prune("s", "a", map[string]any{"horizon": a2}, "admin"), 200)
	expectCode(t, e.get(loc1), 410, "pruned")
	reps, err := archive.Restore(context.Background(), e.e, archive.RestoreOptions{})
	if err != nil || len(reps) != 1 || !reps[0].Cleared {
		t.Fatalf("restore %+v %v", reps, err)
	}
	e.e.FlushCaches()
	expect(t, e.get(loc1), 200)
}

// §E.3.1: the server accepts a declared list in any order, and a prune's
// sealed snapshot needs no list, also when the horizon is a tombstone.
func TestBlobE2EDeclaredOrderAndPrune(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	e := newEnv(t, withKeyStore(newKeyStore(t)), withEncTuning, withArchive(t, dir), withoutRetentionLoop, withoutBlobSweep)
	e.mkNS("e", e2eDoc(map[string]any{}))
	k := seal.NewKey()
	r1 := e.uploadE2E("e", "a", []byte("one"), "alice")
	r2 := e.uploadE2E("e", "a", []byte("two"), "alice")
	b1, b2 := r1["$blob"].(string), r2["$blob"].(string)
	doc := map[string]any{"p": r1, "q": r2}
	r := e.writeAs("e", "a", "", sealedOp(t, k, "e", "a", "", addRoot(doc), b2, b1), "alice")
	expect(t, r, 201)
	a1 := etagOf(r)
	tomb := e.del("e", "a", a1)
	e.clock.Advance(10 * time.Minute)
	snap, err := seal.SealSnapshot(k, "e#1", "e", "a", tomb, doc)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, e.prune("e", "a", map[string]any{"horizon": tomb, "snapshot": snap}, "admin"), 200)
	// The tombstone answers its 410 with the snapshot, the last live
	// document, served as /rev/{H} (§7.1 Paging).
	if r := e.get("/r/e/a/rev/" + tomb); r.Code != 410 || r.Str("code") != "gone" || r.Str("snapshot") != snap || r.H.Get("X-E2E") != "snapshot" {
		t.Fatalf("/rev/{tombstone horizon}: %d %v %s", r.Code, r.H, r.Body)
	}
	// The tombstone's last live document still references both.
	expect(t, e.get(blobPath("e", "a", b1)), 200)
	expect(t, e.get(blobPath("e", "a", b2)), 200)
}

// D.8: every CDN tag purge is sent again by a durable job once the
// staleness bound, replica lag and response deadline have passed.
func TestSecondCDNPurge(t *testing.T) {
	t.Parallel()
	rec := &recPurger{}
	e := newEnv(t, func(o *core.Options) {
		o.Purger = rec
		o.RepurgeDelay = 5 * time.Minute
		o.RepurgeInterval = -1
	})
	e.mkNS("docs", map[string]any{"read": "public"})
	h := e.create("docs", "a", map[string]any{})
	rec.take()
	expect(t, e.do(req{method: "POST", path: "/r/docs/a/purge", ifMatch: h, author: "admin"}), 204)
	if calls := rec.take(); !purged(calls, "r:docs/a") {
		t.Fatalf("first purge %v", calls)
	}
	ctx := context.Background()
	if n, err := e.e.Repurge(ctx); err != nil || n != 0 {
		t.Fatalf("not due yet: %d %v", n, err)
	}
	e.clock.Advance(6 * time.Minute)
	if n, err := e.e.Repurge(ctx); err != nil || n != 1 {
		t.Fatalf("due: %d %v", n, err)
	}
	if calls := rec.take(); len(calls) != 1 || !purged(calls, "r:docs/a") {
		t.Fatalf("second purge %v", calls)
	}
	// Once.
	if n, err := e.e.Repurge(ctx); err != nil || n != 0 || len(rec.take()) != 0 {
		t.Fatalf("again: %d %v", n, err)
	}
	// Config switches to private are purged twice too.
	expect(t, e.patchNS("docs", ops(op("replace", "/read", "grant")), ""), 201)
	if calls := rec.take(); !purged(calls, "ns:docs") {
		t.Fatalf("first purge %v", calls)
	}
	e.clock.Advance(6 * time.Minute)
	if n, err := e.e.Repurge(ctx); err != nil || n != 1 || !purged(rec.take(), "ns:docs") {
		t.Fatalf("second purge of the switch: %d %v", n, err)
	}
	// Writes that purge nothing queue nothing.
	e.create("docs", "b", map[string]any{})
	e.clock.Advance(6 * time.Minute)
	if n, _ := e.e.Repurge(ctx); n != 0 {
		t.Fatalf("a plain write was repurged: %d", n)
	}
}
