package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// Blobs (§7.8).

// withBlobTuning lifts the write rate limits a frozen clock would exhaust.
func withBlobTuning(o *core.Options) {
	l := core.DefaultLimits()
	l.RatePerResource = core.Rate{Rate: 1000, Burst: 1000}
	l.RatePerPrincipal = core.Rate{Rate: 1000, Burst: 1000}
	l.RatePerNamespace = core.Rate{Rate: 1000, Burst: 1000}
	o.Limits, o.Maximums = l, l
	o.BlobSweepInterval = -1
}

func blobID(typ, nonce string, data []byte) string { return ids.Blob(typ, nonce, data).String() }

// ref is a blob reference (§7.8).
func ref(bid, typ string, size int, nonce string) map[string]any {
	m := map[string]any{"$blob": bid, "type": typ, "size": size}
	if nonce != "" {
		m["nonce"] = nonce
	}
	return m
}

func (e *tenv) who(q *req, who []string) {
	if len(who) > 0 {
		if e.auth {
			q.bearer = who[0]
		} else {
			q.author = who[0]
		}
	} else {
		q.author = "alice"
	}
}

// putBlob uploads data as bid (computed unless given) and returns the answer.
func (e *tenv) putBlob(ns, name, typ, nonce string, data []byte, who ...string) (*resp, string) {
	e.t.Helper()
	bid := blobID(strings.ToLower(strings.TrimSpace(strings.Split(typ, ";")[0])), nonce, data)
	return e.putBlobAs(ns, name, bid, typ, nonce, data, who...), bid
}

func (e *tenv) putBlobAs(ns, name, bid, typ, nonce string, data []byte, who ...string) *resp {
	e.t.Helper()
	q := req{method: "PUT", path: "/r/" + ns + "/" + name + "/blob/" + bid, raw: string(data), hasRaw: true, ct: typ, hdr: map[string]string{}}
	if nonce != "" {
		q.hdr["Blob-Nonce"] = nonce
	}
	e.who(&q, who)
	return e.do(q)
}

// upload uploads and expects 201.
func (e *tenv) upload(ns, name, typ string, data []byte, who ...string) string {
	e.t.Helper()
	r, bid := e.putBlob(ns, name, typ, "", data, who...)
	expect(e.t, r, 201)
	if etagOf(r) != bid {
		e.t.Fatalf("ETag %q, want %q", r.H.Get("ETag"), bid)
	}
	return bid
}

func (e *tenv) copyBlob(ns, name, bid, from, srcGrant string, who ...string) *resp {
	e.t.Helper()
	q := req{method: "PUT", path: "/r/" + ns + "/" + name + "/blob/" + bid, hdr: map[string]string{"Blob-From": from}}
	if srcGrant != "" {
		q.hdr["Source-Authorization"] = "Bearer " + srcGrant
	}
	e.who(&q, who)
	return e.do(q)
}

func (e *tenv) blobStats() *core.BlobStats {
	e.t.Helper()
	s, err := e.e.BlobStats(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func blobPath(ns, name, bid string) string { return "/r/" + ns + "/" + name + "/blob/" + bid }

// §7.8: upload, pending invisibility, attach at write, read with ranges and
// immutable caching, idempotent re-uploads.
func TestBlobUploadAndRead(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("m", map[string]any{"read": "public"})
	data := []byte("hello, blob world: " + strings.Repeat("x", 100))
	bid := e.upload("m", "a", "Text/Plain; charset=utf-8", data)
	if bid != blobID("text/plain", "", data) {
		t.Fatal("the id is over the lowercased type without parameters")
	}
	// Pending: invisible, even to its uploader.
	expectCode(t, e.get(blobPath("m", "a", bid)), 404, "not_found")
	// Idempotent.
	expect(t, e.putBlobAs("m", "a", bid, "text/plain", "", data), 201)

	// A write that references it attaches it.
	head := e.create("m", "a", map[string]any{"body": ref(bid, "text/plain", len(data), "")})
	r := e.get(blobPath("m", "a", bid))
	expect(t, r, 200)
	if string(r.Body) != string(data) || r.H.Get("Content-Type") != "text/plain" || etagOf(r) != bid ||
		r.H.Get("Accept-Ranges") != "bytes" {
		t.Fatalf("blob answer %v %q", r.H, r.Body)
	}
	if r.H.Get("Cache-Control") != ccImmutable || r.H.Get("Cache-Tag") != "ns:m,r:m/a" || r.H.Get("Surrogate-Key") != "ns:m r:m/a" {
		t.Fatalf("caching %v", r.H)
	}
	// Ranges and conditional requests.
	rr := e.do(req{method: "GET", path: blobPath("m", "a", bid), hdr: map[string]string{"Range": "bytes=7-10"}})
	expect(t, rr, 206)
	if string(rr.Body) != "blob" || rr.H.Get("Content-Range") != "bytes 7-10/"+strconv.Itoa(len(data)) {
		t.Fatalf("range %v %q", rr.H, rr.Body)
	}
	expect(t, e.do(req{method: "GET", path: blobPath("m", "a", bid), hdr: map[string]string{"If-None-Match": quote(bid)}}), 304)
	expect(t, e.do(req{method: "HEAD", path: blobPath("m", "a", bid)}), 200)
	// Unknown blobs are short-cached 404s.
	other := blobID("text/plain", "", []byte("nope"))
	u := e.get(blobPath("m", "a", other))
	expectCode(t, u, 404, "not_found")
	if u.H.Get("Cache-Control") != ccShort {
		t.Fatalf("404 caching %v", u.H)
	}
	// Not another resource's.
	expect(t, e.get(blobPath("m", "b", bid)), 404)

	// Later writes keep referencing it with no pending entry.
	head = e.appendRev("m", "a", head, ops(op("add", "/copy", ref(bid, "text/plain", len(data), ""))))
	// A reference must match type, size and nonce.
	for name, bad := range map[string]map[string]any{
		"size":  ref(bid, "text/plain", len(data)+1, ""),
		"type":  ref(bid, "text/html", len(data), ""),
		"nonce": ref(bid, "text/plain", len(data), seal.NewNonce()),
	} {
		r := e.write("PATCH", "m", "a", head, ops(op("add", "/bad", bad)))
		if r.Code != 422 || r.Str("code") != "blob" || r.Str("pointer") != "/bad" {
			t.Errorf("%s mismatch: %d %s", name, r.Code, r.Body)
		}
	}
	// An unknown blob is unavailable.
	expectCode(t, e.write("PATCH", "m", "a", head, ops(op("add", "/x", ref(other, "text/plain", 4, "")))), 422, "blob")
	s := e.blobStats()
	if s.Attached != 1 || s.Pending != 0 || s.Bytes != 1 {
		t.Fatalf("stats %+v", s)
	}
	// A nonce is part of the id (§3.7).
	nonce := seal.NewNonce()
	r2, nbid := e.putBlob("m", "a", "image/png", nonce, data)
	expect(t, r2, 201)
	if nbid == blobID("image/png", "", data) {
		t.Fatal("nonce not hashed")
	}
	expect(t, e.write("PATCH", "m", "a", head, ops(op("add", "/img", ref(nbid, "image/png", len(data), nonce)))), 201)
	expect(t, e.get(blobPath("m", "a", nbid)), 200)
	// Same bytes, stored once.
	if s := e.blobStats(); s.Bytes != 1 || s.Attached != 2 {
		t.Fatalf("stats %+v", s)
	}
}

// §7.8: the checks of an upload, in order.
func TestBlobUploadChecks(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("c", map[string]any{"limits": map[string]any{"blobSize": 1000, "blobPending": 10000}})
	data := []byte("some bytes")
	bid := blobID("text/plain", "", data)

	expectCode(t, e.putBlobAs("c", "a", bid, "nonsense", "", data), 400, "bad_input")
	expectCode(t, e.putBlobAs("c", "a", bid, "text/plain", "short", data), 400, "bad_input")
	expectCode(t, e.putBlobAs("c", "a", "1abc", "text/plain", "", data), 400, "bad_input")
	expectCode(t, e.putBlobAs("c", "a", bid, "text/html", "", data), 422, "blob_mismatch")
	expectCode(t, e.putBlobAs("c", "a", bid, "text/plain", "", []byte("other bytes")), 422, "blob_mismatch")
	big := []byte(strings.Repeat("b", 1001))
	r, _ := e.putBlob("c", "a", "text/plain", "", big)
	expectCode(t, r, 413, "limit")
	// blobPending: at least 4 KiB per blob, per uploader and namespace.
	expect(t, e.putBlobAs("c", "a", bid, "text/plain", "", data), 201)
	expect(t, e.putBlobAs("c", "a", bid, "text/plain", "", data), 201) // the same entry again
	r, _ = e.putBlob("c", "b", "text/plain", "", []byte("two"))
	expect(t, r, 201)
	r, _ = e.putBlob("c", "b", "text/plain", "", []byte("three"))
	expectCode(t, r, 413, "limit") // 3 × 4 KiB > 10000
	r, _ = e.putBlob("c", "b", "text/plain", "", []byte("three"), "bob")
	expect(t, r, 201) // bob's own budget

	// A frozen namespace is 409, before the type is looked at.
	cid := e.configID("c")
	expect(t, e.do(req{method: "PATCH", path: "/ns/c", ifMatch: cid, author: "admin", body: ops(op("add", "/frozen", true))}), 201)
	expectCode(t, e.putBlobAs("c", "a", bid, "nonsense", "", data), 409, "frozen")
	cid = e.configID("c")
	expect(t, e.do(req{method: "PATCH", path: "/ns/c", ifMatch: cid, author: "admin", body: ops(op("replace", "/frozen", false))}), 201)

	// A purged resource is 410.
	h := e.create("c", "p", map[string]any{"n": 1})
	expect(t, e.do(req{method: "POST", path: "/r/c/p/purge", ifMatch: h, author: "admin"}), 204)
	expectCode(t, e.putBlobAs("c", "p", bid, "nonsense", "", data), 410, "gone")

	// blobGrace must be at least retryWindow.
	cid = e.configID("c")
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/c", ifMatch: cid, author: "admin",
		body: ops(op("add", "/limits/blobGrace", "PT1M"))}), 422, "limit")
	expect(t, e.do(req{method: "PATCH", path: "/ns/c", ifMatch: cid, author: "admin",
		body: ops(op("add", "/limits/blobGrace", "PT10M"))}), 201)
	cid = e.configID("c")
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/c", ifMatch: cid, author: "admin",
		body: ops(op("add", "/limits/blobSize", 1<<40))}), 422, "limit")
}

// §6.6: blobRate draws an upload's bytes; a copy draws none.
func TestBlobRate(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("r", map[string]any{"read": "public", "limits": map[string]any{"blobRate": map[string]any{"rate": 1, "burst": 1000}}})
	a := []byte(strings.Repeat("a", 1500))
	r, bid := e.putBlob("r", "x", "text/plain", "", a)
	expect(t, r, 201) // admitted with tokens left, then below zero
	r, _ = e.putBlob("r", "x", "text/plain", "", []byte("tiny"))
	expectCode(t, r, 429, "rate")
	if r.Str("limit") != "blobRate" || r.H.Get("Retry-After") == "" {
		t.Fatalf("429 %v %s", r.H, r.Body)
	}
	// Another principal has its own bucket.
	r, _ = e.putBlob("r", "x", "text/plain", "", []byte("tiny"), "bob")
	expect(t, r, 201)
	// Copies cost no bytes.
	e.create("r", "x", map[string]any{"a": ref(bid, "text/plain", len(a), "")})
	expect(t, e.copyBlob("r", "y", bid, blobPath("r", "x", bid), ""), 201)
}

// §7.8: each uploader has its own pending entry; only it can reference it;
// once attached, any writer can.
func TestBlobPendingPerUploader(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("p", map[string]any{})
	data := []byte("shared bytes")
	bid := e.upload("p", "a", "text/plain", data, "alice")
	doc := map[string]any{"b": ref(bid, "text/plain", len(data), "")}
	expectCode(t, e.write("PATCH", "p", "a", "", addRoot(doc), "bob"), 422, "blob")
	expect(t, e.putBlobAs("p", "a", bid, "text/plain", "", data, "bob"), 201)
	if s := e.blobStats(); s.Pending != 2 || s.Bytes != 1 {
		t.Fatalf("stats %+v", s)
	}
	head := e.create("p", "a", doc, "alice")
	// Attaching deleted every pending entry; bob references the attachment.
	if s := e.blobStats(); s.Pending != 0 || s.Attached != 1 || s.Bytes != 1 {
		t.Fatalf("stats %+v", s)
	}
	expect(t, e.write("PATCH", "p", "a", head, ops(op("add", "/again", ref(bid, "text/plain", len(data), ""))), "carol"), 201)
	// Pending in one resource isn't available to another.
	bid2 := e.upload("p", "x", "text/plain", []byte("for x"), "alice")
	expectCode(t, e.write("PATCH", "p", "y", "", addRoot(map[string]any{"b": ref(bid2, "text/plain", 5, "")}), "alice"), 422, "blob")
}

// §7.8: a pending entry expires after blobGrace; uploading again restarts
// it; the sweep deletes entries and bytes.
func TestBlobGrace(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("g", map[string]any{"limits": map[string]any{"blobGrace": "PT1H"}})
	data := []byte("short-lived")
	bid := e.upload("g", "a", "text/plain", data)
	doc := map[string]any{"b": ref(bid, "text/plain", len(data), "")}
	e.clock.Advance(50 * time.Minute)
	expect(t, e.putBlobAs("g", "a", bid, "text/plain", "", data), 201) // restarts
	e.clock.Advance(50 * time.Minute)
	if n, err := e.e.SweepBlobs(context.Background()); err != nil || n != 0 {
		t.Fatalf("sweep %d %v", n, err)
	}
	// Still pending 50 minutes after the re-upload.
	e.clock.Advance(11 * time.Minute)
	expectCode(t, e.write("PATCH", "g", "a", "", addRoot(doc)), 422, "blob")
	n, err := e.e.SweepBlobs(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("sweep %d %v", n, err)
	}
	if s := e.blobStats(); s.Pending != 0 || s.Bytes != 0 {
		t.Fatalf("stats %+v", s)
	}
	// An expired entry doesn't count toward blobPending either.
	expect(t, e.putBlobAs("g", "a", bid, "text/plain", "", data), 201)
	expect(t, e.write("PATCH", "g", "a", "", addRoot(doc)), 201)
}

// §8.1, §8.3: a tombstoned resource keeps serving its blobs; a purge ends
// every attachment (410) and deletes the bytes.
func TestBlobTombstoneAndPurge(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("d", map[string]any{"read": "public"})
	data := []byte("purgeable")
	bid := e.upload("d", "a", "text/plain", data)
	head := e.create("d", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	pend := e.upload("d", "a", "text/plain", []byte("pending too"))
	tomb := e.del("d", "a", head)
	expect(t, e.get(blobPath("d", "a", bid)), 200)
	// The same bytes in another resource are a separate attachment.
	bidB := e.upload("d", "b", "text/plain", data)
	e.create("d", "b", map[string]any{"b": ref(bidB, "text/plain", len(data), "")})
	expect(t, e.do(req{method: "POST", path: "/r/d/a/purge", ifMatch: tomb, author: "admin"}), 204)
	r := e.get(blobPath("d", "a", bid))
	expectCode(t, r, 410, "gone")
	if r.H.Get("Cache-Control") != ccLong {
		t.Fatalf("410 caching %v", r.H)
	}
	expect(t, e.get(blobPath("d", "a", pend)), 410)
	expect(t, e.get(blobPath("d", "b", bidB)), 200)
	if s := e.blobStats(); s.Attached != 1 || s.Pending != 0 || s.Bytes != 1 {
		t.Fatalf("stats %+v", s)
	}
	h := e.head("d", "b")
	expect(t, e.do(req{method: "POST", path: "/r/d/b/purge", ifMatch: h, author: "admin"}), 204)
	if s := e.blobStats(); s.Attached != 0 || s.Bytes != 0 {
		t.Fatalf("stats after the last purge %+v", s)
	}
}

// §8.5: a namespace purge clears its blobs.
func TestBlobNamespacePurge(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("z", map[string]any{})
	data := []byte("ns purge")
	bid := e.upload("z", "a", "text/plain", data)
	e.create("z", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	e.upload("z", "b", "text/plain", []byte("pending"))
	expect(t, e.patchNS("z", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/z/purge", ifMatch: e.nsHead("z"), author: "admin"}), 204)
	expect(t, e.get(blobPath("z", "a", bid)), 410)
	if s := e.blobStats(); s.Attached != 0 || s.Pending != 0 || s.Bytes != 0 {
		t.Fatalf("stats %+v", s)
	}
}

// §7.6, §7.8: a branch reads its base's blobs through as of at, attaches
// them at its first write, and purges propagate.
func TestBlobBranch(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("base", map[string]any{"read": "public"})
	data := []byte("base blob")
	bid := e.upload("base", "a", "text/plain", data)
	head := e.create("base", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	at := e.nsHead("base")
	// Attached in the base after at: not in the branch's view.
	late := []byte("late blob")
	lbid := e.upload("base", "a", "text/plain", late)
	e.appendRev("base", "a", head, ops(op("add", "/late", ref(lbid, "text/plain", len(late), ""))))
	expect(t, e.do(req{method: "POST", path: "/ns/base/branches", ifNoneMatch: "*", author: "admin",
		body: map[string]any{"name": "br", "at": at, "patches": []any{}}}), 201)

	expect(t, e.get(blobPath("br", "a", bid)), 200)
	expect(t, e.get(blobPath("br", "a", lbid)), 404)
	// A first write referencing a base blob: available, and attached to
	// the branch's own resource.
	bh := e.appendRev("br", "a", head, ops(op("add", "/x", 1), op("add", "/again", ref(bid, "text/plain", len(data), ""))))
	expectCode(t, e.write("PATCH", "br", "a", bh, ops(op("add", "/l", ref(lbid, "text/plain", len(late), "")))), 422, "blob")
	// A branch blob of its own.
	own := []byte("branch blob")
	obid := e.upload("br", "a", "text/plain", own)
	bh = e.appendRev("br", "a", bh, ops(op("add", "/own", ref(obid, "text/plain", len(own), ""))))
	expect(t, e.get(blobPath("br", "a", obid)), 200)
	expect(t, e.get(blobPath("base", "a", obid)), 404)
	// Read-through of a resource the branch never wrote.
	d2 := []byte("other")
	b2 := e.upload("base", "c", "text/plain", d2)
	e.create("base", "c", map[string]any{"b": ref(b2, "text/plain", len(d2), "")})
	expect(t, e.get(blobPath("br", "c", b2)), 404) // after at

	// A purge in the base propagates to the branch.
	bhead := e.head("base", "a")
	expect(t, e.do(req{method: "POST", path: "/r/base/a/purge", ifMatch: bhead, author: "admin"}), 204)
	expect(t, e.get(blobPath("br", "a", bid)), 410)
	expect(t, e.get(blobPath("br", "a", obid)), 410)
	expect(t, e.get(blobPath("base", "a", bid)), 410)
}

// §7.5, §7.8: a batch with a local source may reference the blobs attached
// in the source as of source.at; merges copy nothing.
func TestBlobBatchSource(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("main", map[string]any{"read": "public"})
	head := e.create("main", "a", map[string]any{"n": 0})
	expect(t, e.do(req{method: "POST", path: "/ns/main/branches", ifNoneMatch: "*", author: "admin",
		body: map[string]any{"name": "feat", "at": e.nsHead("main"), "patches": []any{}}}), 201)
	data := []byte("from the branch")
	bid := e.upload("feat", "a", "text/plain", data, "bob")
	patches := ops(op("add", "/b", ref(bid, "text/plain", len(data), "")))
	e.appendRev("feat", "a", head, patches, "bob")
	at := e.nsHead("feat")
	batch := func(source map[string]any) *resp {
		body := map[string]any{"items": []any{map[string]any{"resource": "a", "ifMatch": head, "steps": []any{patches}}}}
		if source != nil {
			body["source"] = source
		}
		return e.do(req{method: "POST", path: "/ns/main/batch", author: "merger", body: body})
	}
	expectCode(t, batch(nil), 422, "batch")
	// A source.at outside the source's chain makes nothing available.
	expectCode(t, batch(map[string]any{"ns": "feat", "at": e.nsHead("main")}), 422, "batch")
	r := batch(map[string]any{"ns": "feat", "at": at})
	expect(t, r, 201)
	if s := e.blobStats(); s.Attached != 2 || s.Bytes != 1 {
		t.Fatalf("stats %+v", s)
	}
	expect(t, e.get(blobPath("main", "a", bid)), 200)
}

// §7.5: the source's history as of source.at decides.
func TestBlobBatchSourceAsOf(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("main", map[string]any{})
	head := e.create("main", "a", map[string]any{"n": 0})
	expect(t, e.do(req{method: "POST", path: "/ns/main/branches", ifNoneMatch: "*", author: "admin",
		body: map[string]any{"name": "feat", "at": e.nsHead("main"), "patches": []any{}}}), 201)
	before := e.nsHead("feat")
	data := []byte("later")
	bid := e.upload("feat", "a", "text/plain", data)
	patches := ops(op("add", "/b", ref(bid, "text/plain", len(data), "")))
	e.appendRev("feat", "a", head, patches)
	body := map[string]any{"items": []any{map[string]any{"resource": "a", "ifMatch": head, "steps": []any{patches}}},
		"source": map[string]any{"ns": "feat", "at": before}}
	expectCode(t, e.do(req{method: "POST", path: "/ns/main/batch", author: "merger", body: body}), 422, "batch")
}

// §8.6: pruning ends attachments no kept document references (410 as
// pruned), and the archive carries their blobs as blob lines (§G.4.1).
func TestBlobPrune(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, withBlobTuning, withArchive(t, dir), withoutRetentionLoop)
	e.mkNS("main", map[string]any{"read": "public"})
	da, db, dk := []byte("old blob A"), []byte("new blob B"), []byte("kept blob K")
	ba := e.upload("main", "r", "text/plain", da)
	bk := e.upload("main", "r", "text/plain", dk)
	revs := []string{e.create("main", "r", map[string]any{"a": ref(ba, "text/plain", len(da), "")})}
	revs = append(revs, e.appendRev("main", "r", revs[0], ops(op("remove", "/a"), op("add", "/k", ref(bk, "text/plain", len(dk), "")))))
	revs = append(revs, e.appendRev("main", "r", revs[1], ops(op("remove", "/k"))))
	bb := e.upload("main", "r", "text/plain", db)
	revs = append(revs, e.appendRev("main", "r", revs[2], ops(op("add", "/b", ref(bb, "text/plain", len(db), "")))))
	e.clock.Advance(time.Hour)
	r := e.prune("main", "r", map[string]any{"horizon": revs[3], "keep": []any{revs[1]}}, "admin")
	expect(t, r, 200)
	g := e.get(blobPath("main", "r", ba))
	expectCode(t, g, 410, "pruned")
	if g.Str("horizon") != revs[3] || g.Str("archive") == "" || g.H.Get("Cache-Control") != ccPruned || g.H.Get("Cache-Tag") != "ns:main,r:main/r" {
		t.Fatalf("pruned blob %v %s", g.H, g.Body)
	}
	expect(t, e.get(blobPath("main", "r", bk)), 200) // a kept document references it
	expect(t, e.get(blobPath("main", "r", bb)), 200)
	if s := e.blobStats(); s.Attached != 2 || s.Pruned != 1 || s.Bytes != 2 {
		t.Fatalf("stats %+v", s)
	}
	// The archive has blob lines for A and K, each before the first line
	// that references it, and verifies.
	p := filepath.Join(dir, "main", "r", revs[3]+".jsonl")
	verifyArchive(t, p)
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var order []string
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<24)
	for sc.Scan() {
		m, _ := jsonv.MustParse(sc.Bytes()).(map[string]any)
		switch {
		case m["blob"] != nil:
			d, _ := base64.RawURLEncoding.DecodeString(m["data"].(string))
			order = append(order, "blob:"+string(d))
		case m["id"] != nil:
			order = append(order, "rev:"+m["id"].(string))
		}
	}
	want := []string{"blob:" + string(da), "rev:" + revs[0], "blob:" + string(dk), "rev:" + revs[1], "rev:" + revs[2]}
	if strings.Join(order, " ") != strings.Join(want, " ") {
		t.Fatalf("archive lines %v, want %v", order, want)
	}
	// Re-referencing a pruned blob needs it available again: re-upload.
	head := revs[3]
	expectCode(t, e.write("PATCH", "main", "r", head, ops(op("add", "/a", ref(ba, "text/plain", len(da), "")))), 422, "blob")
	e.upload("main", "r", "text/plain", da)
	expect(t, e.write("PATCH", "main", "r", head, ops(op("add", "/a", ref(ba, "text/plain", len(da), "")))), 201)
	expect(t, e.get(blobPath("main", "r", ba)), 200)
	// Restoring the archive reads past its blob lines.
	reps, err := archive.Restore(context.Background(), e.e, archive.RestoreOptions{})
	if err != nil || len(reps) != 1 || len(reps[0].Failed) != 0 || reps[0].Restored != 3 || !reps[0].Cleared {
		t.Fatalf("restore %+v %v", reps, err)
	}
}

// §6.6: an allowance may raise blobPending and blobRate for its principal.
func TestBlobAllowance(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("a", map[string]any{
		"limits":     map[string]any{"blobPending": 5000, "blobRate": map[string]any{"rate": 1, "burst": 100}},
		"allowances": []any{map[string]any{"sub": "importer", "kid": "k", "blobPending": 100000, "blobRate": map[string]any{"rate": 1, "burst": 100000}}},
	})
	big := []byte(strings.Repeat("i", 2000))
	for i := 0; i < 3; i++ {
		r, _ := e.putBlob("a", "x", "text/plain", "", append(big, byte('0'+i)), "importer")
		expect(t, r, 201)
	}
	r, _ := e.putBlob("a", "x", "text/plain", "", big, "alice")
	expect(t, r, 201) // below zero now
	r, _ = e.putBlob("a", "x", "text/plain", "", []byte("again"), "alice")
	expectCode(t, r, 429, "rate")
	// Allowance limits are bounded by the deployment's.
	cid := e.configID("a")
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/a", ifMatch: cid, author: "admin",
		body: ops(op("replace", "/allowances/0/blobPending", 1<<40))}), 422, "limit")
}

// D.2, D.8: bytes shared by two namespaces survive a purge of one of them
// racing an upload of the same bytes into the other (the collector and the
// uploader are ordered by the bytes row's lock on Postgres).
func TestBlobPurgeRacesUpload(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("one", map[string]any{"read": "public"})
	e.mkNS("two", map[string]any{"read": "public"})
	for i := 0; i < 10; i++ {
		data := []byte("shared " + strconv.Itoa(i))
		name := "r" + strconv.Itoa(i)
		bid := e.upload("one", name, "text/plain", data)
		head := e.create("one", name, map[string]any{"b": ref(bid, "text/plain", len(data), "")})
		done := make(chan *resp)
		go func() {
			done <- e.do(req{method: "POST", path: "/r/one/" + name + "/purge", ifMatch: head, author: "admin"})
		}()
		up := e.putBlobAs("two", name, bid, "text/plain", "", data)
		if r := <-done; r.Code != 204 || up.Code != 201 {
			t.Fatalf("purge %d, upload %d", r.Code, up.Code)
		}
		expect(t, e.write("PATCH", "two", name, "", addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")})), 201)
		g := e.get(blobPath("two", name, bid))
		expect(t, g, 200)
		if string(g.Body) != string(data) {
			t.Fatalf("bytes %q", g.Body)
		}
	}
}

// §7.8 Copying: ranks, read checks, and the 404s that reveal nothing.
func TestBlobCopy(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("pub", map[string]any{"read": "public"})
	e.mkNS("pub2", map[string]any{"read": "public"})
	e.mkNS("priv", map[string]any{"read": "grant"})
	data := []byte("copy me")
	bid := e.upload("pub", "a", "text/plain", data)
	e.create("pub", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	pbid := e.upload("priv", "a", "text/plain", data)
	if pbid != bid {
		t.Fatal("same bytes, same id")
	}
	e.create("priv", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	pending := e.upload("pub", "p", "text/plain", []byte("pending"))

	from := blobPath("pub", "a", bid)
	expect(t, e.copyBlob("pub2", "x", bid, from, ""), 201)
	expect(t, e.write("PATCH", "pub2", "x", "", addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")})), 201)
	expect(t, e.get(blobPath("pub2", "x", bid)), 200)
	// Public into private: allowed.
	expect(t, e.copyBlob("priv", "y", bid, from, ""), 201)
	// Private into public: a higher rank, 404.
	expectCode(t, e.copyBlob("pub2", "z", bid, blobPath("priv", "a", bid), ""), 404, "not_found")
	// Another id: 422; malformed: 400.
	other := blobID("text/plain", "", []byte("x"))
	expectCode(t, e.copyBlob("pub2", "z", other, from, ""), 422, "blob")
	expectCode(t, e.copyBlob("pub2", "z", bid, "/r/pub/a/rev/"+bid, ""), 400, "bad_input")
	// Pending, unknown, purged, or a missing namespace: 404.
	expect(t, e.copyBlob("pub2", "z", pending, blobPath("pub", "p", pending), ""), 404)
	expect(t, e.copyBlob("pub2", "z", bid, blobPath("pub", "nothing", bid), ""), 404)
	expect(t, e.copyBlob("pub2", "z", bid, blobPath("nons", "a", bid), ""), 404)
	// A copy with a body is 400, after the source checks.
	q := req{method: "PUT", path: blobPath("pub2", "z", bid), raw: "body", hasRaw: true, ct: "text/plain", author: "alice",
		hdr: map[string]string{"Blob-From": from}}
	expectCode(t, e.do(q), 400, "bad_input")
	// The copy's type, nonce and size apply (blobSize).
	cid := e.configID("pub2")
	expect(t, e.do(req{method: "PATCH", path: "/ns/pub2", ifMatch: cid, author: "admin", body: ops(op("add", "/limits", map[string]any{"blobSize": 3}))}), 201)
	expectCode(t, e.copyBlob("pub2", "w", bid, from, ""), 413, "limit")
	// After a purge of the source: 404.
	expect(t, e.do(req{method: "POST", path: "/r/pub/a/purge", ifMatch: e.head("pub", "a"), author: "admin"}), 204)
	expect(t, e.copyBlob("priv", "v", bid, from, ""), 404)
	// The copies stay (§8.3).
	expect(t, e.get(blobPath("pub2", "x", bid)), 200)
}

// §7.8: copies into e2e need a sealed blob; uploads of other types are 415.
func TestBlobE2EType(t *testing.T) {
	e := newEnv(t, withKeyStore(newKeyStore(t)), withEncTuning)
	e.mkNS("e", e2eDoc(map[string]any{}))
	r, _ := e.putBlob("e", "a", "image/png", "", []byte("plain"))
	expect(t, r, 415)
	r, _ = e.putBlob("e", "a", core.SealedBlobType, "", []byte("ciphertext"))
	expect(t, r, 201)
	e.mkNS("pub", map[string]any{"read": "public"})
	data := []byte("public bytes")
	bid := e.upload("pub", "a", "text/plain", data)
	e.create("pub", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	expect(t, e.copyBlob("e", "a", bid, blobPath("pub", "a", bid), ""), 415)
}

// §E.2.2: sealed namespaces serve nothing until the sealed form exists.
func TestBlobSealedNotServed(t *testing.T) {
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	data := []byte("secret blob")
	nonce := seal.NewNonce()
	r, bid := e.putBlob("s", "a", "text/plain", nonce, data)
	expect(t, r, 201)
	expect(t, e.write("PATCH", "s", "a", "", withNonce(addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), nonce)}))), 201)
	g := e.get(blobPath("s", "a", bid))
	expect(t, g, 501)
	if strings.Contains(string(g.Body), string(data)) {
		t.Fatal("plaintext served")
	}
}

// §E.1: blob bytes of encrypted namespaces are encrypted at rest, under
// each resource's key; a purge leaves nothing recoverable.
func TestBlobAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blobs.db")
	e := newEnv(t, withKeyStore(newKeyStore(t)), withEncTuning, withPath(path))
	e.mkNS("enc", atRest(map[string]any{"read": "public"}))
	e.mkNS("plain", map[string]any{"read": "public"})
	data := []byte("blob " + encMarker + " bytes " + strings.Repeat("z", 64))
	bid := e.upload("enc", "a", "text/plain", data)
	head := e.create("enc", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	if e.upload("enc", "c", "text/plain", data) != bid { // pending in another resource
		t.Fatal("same bytes, same id")
	}
	r := e.get(blobPath("enc", "a", bid))
	expect(t, r, 200)
	if string(r.Body) != string(data) {
		t.Fatal("decrypted bytes differ")
	}
	assertNoPlaintext(t, path)
	if s := e.blobStats(); s.Encrypted != 2 || s.Bytes != 2 {
		t.Fatalf("stats %+v: one copy per resource", s)
	}
	// A copy into a plaintext namespace stores plaintext there.
	expect(t, e.copyBlob("plain", "x", bid, blobPath("enc", "a", bid), ""), 201)
	if s := e.blobStats(); s.Bytes != 3 || s.Encrypted != 2 {
		t.Fatalf("stats %+v", s)
	}
	expect(t, e.do(req{method: "POST", path: "/r/enc/a/purge", ifMatch: head, author: "admin"}), 204)
	if s := e.blobStats(); s.Encrypted != 1 {
		t.Fatalf("stats after purge %+v", s)
	}
	if n := queryInt(t, path, `SELECT COUNT(*) FROM blob_bytes WHERE owner IN (SELECT res FROM resources WHERE name = 'a' AND ns = (SELECT ns FROM namespaces WHERE name = 'enc'))`); n != 0 {
		t.Fatalf("%d byte rows of the purged resource remain", n)
	}
}

// §E.1: turning encryption on moves plaintext blob bytes under the
// resource's key.
func TestBlobEncryptLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "later.db")
	e := newEnv(t, withKeyStore(newKeyStore(t)), withEncTuning, withPath(path))
	e.mkNS("n", map[string]any{"read": "public"})
	data := []byte("later " + encMarker)
	bid := e.upload("n", "a", "text/plain", data)
	e.create("n", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	e.upload("n", "b", "text/plain", data)
	if !storedAnywhere(t, path, encMarker) {
		t.Fatal("expected plaintext before encryption")
	}
	expect(t, e.patchNS("n", ops(op("add", "/encryption", map[string]any{"level": "at-rest"})), ""), 201)
	checkpoint(t, path)
	if storedAnywhere(t, path, encMarker) {
		t.Fatal("plaintext blob bytes remain after encryption")
	}
	if s := e.blobStats(); s.Encrypted != 2 || s.Bytes != 2 {
		t.Fatalf("stats %+v", s)
	}
	expect(t, e.get(blobPath("n", "a", bid)), 200)
}

// §C.5, §7.8: access to a blob is read access to its resource.
func TestBlobAccess(t *testing.T) {
	f := newAuthFixture(t, nil, withBlobTuning)
	e := f.tenv
	data := []byte("private bytes")
	bid := e.upload("sec", "a", "text/plain", data, f.issuerG)
	e.create("sec", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")}, f.issuerG)
	r := e.get(blobPath("sec", "a", bid), f.issuerG)
	expect(t, r, 200)
	if !strings.HasPrefix(r.H.Get("Cache-Control"), "private") {
		t.Fatalf("private caching %v", r.H)
	}
	expectCode(t, e.get(blobPath("sec", "a", bid)), 401, "unauthenticated")
	onlyB := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "b"}}})
	expectCode(t, e.get(blobPath("sec", "a", bid), onlyB), 404, "not_found")
	onlyA := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	expect(t, e.get(blobPath("sec", "a", bid), onlyA), 200)

	// Uploading needs create, append or restore on the resource.
	readOnly := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read"})
	r2, _ := e.putBlob("sec", "a", "text/plain", "", []byte("x"), readOnly)
	expectCode(t, r2, 403, "forbidden")
	appendB := e.grant(f.issuer, "user:w", []string{"sec"}, []string{"append"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "b"}}})
	r2, _ = e.putBlob("sec", "a", "text/plain", "", []byte("x"), appendB)
	expect(t, r2, 403)
	r2, _ = e.putBlob("sec", "b", "text/plain", "", []byte("x"), appendB)
	expect(t, r2, 201)
	// Authorisation comes before everything else.
	expect(t, e.putBlobAs("sec", "a", bid, "nonsense", "", data, readOnly), 403)
	expect(t, e.putBlobAs("sec", "a", bid, "text/plain", "", data), 401)
	// Uploaders are root sub and kid: bob's pending blob isn't another
	// principal's.
	other := e.grant(f.issuer, "user:carol", []string{"sec"}, []string{"read", "create", "append"})
	pb := e.upload("sec", "n", "text/plain", []byte("bob's"), f.issuerG)
	expectCode(t, e.write("PATCH", "sec", "n", "", addRoot(map[string]any{"b": ref(pb, "text/plain", 5, "")}), other), 422, "blob")
	expect(t, e.write("PATCH", "sec", "n", "", addRoot(map[string]any{"b": ref(pb, "text/plain", 5, "")}), f.issuerG), 201)
}

// §7.8 Copying with Source-Authorization, and the batch source read check.
func TestBlobSourceAuthorization(t *testing.T) {
	f := newAuthFixture(t, nil, withBlobTuning)
	e := f.tenv
	// A second namespace with its own keys: the issuer's grant can't read
	// it, a grant of its own key can.
	k2 := newKey("k2")
	e.mkNS("other", map[string]any{"read": "grant", "keys": []any{k2.entry("read", "create", "append")}})
	og := e.grant(k2, "user:o", []string{"other"}, []string{"read", "create", "append"})
	data := []byte("in other")
	bid := e.upload("other", "a", "text/plain", data, og)
	e.create("other", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")}, og)
	from := blobPath("other", "a", bid)
	expectCode(t, e.copyBlob("sec", "x", bid, from, "", f.issuerG), 404, "not_found")
	// A bad Source-Authorization is a 404 too.
	expect(t, e.copyBlob("sec", "x", bid, from, "garbage", f.issuerG), 404)
	expect(t, e.copyBlob("sec", "x", bid, from, og, f.issuerG), 201)
	expect(t, e.write("PATCH", "sec", "x", "", addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")}), f.issuerG), 201)
	// The read check on the source is a read of the resource.
	onlyB := e.grant(k2, "user:o", []string{"other"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "b"}}})
	expect(t, e.copyBlob("sec", "y", bid, from, onlyB, f.issuerG), 404)

	// A batch whose source is another namespace: the same resource there,
	// read with Source-Authorization.
	at := e.nsHead("other", og)
	item := map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")})}}
	body := map[string]any{"items": []any{item}, "source": map[string]any{"ns": "other", "at": at}}
	expectCode(t, e.do(req{method: "POST", path: "/ns/sec/batch", bearer: f.issuerG, body: body}), 422, "batch")
	expect(t, e.do(req{method: "POST", path: "/ns/sec/batch", bearer: f.issuerG, body: body,
		hdr: map[string]string{"Source-Authorization": "Bearer " + og}}), 201)
}

// D.2, D.3: the re-check under the write lock confirms the blobs are
// still available; a pending entry swept between check and insert fails the
// write instead of attaching missing bytes.
func TestBlobRecheck(t *testing.T) {
	var hook func()
	e := newEnv(t, withBlobTuning, func(o *core.Options) {
		o.BeforeWriteLock = func() {
			if h := hook; h != nil {
				hook = nil
				h()
			}
		}
	})
	e.mkNS("r", map[string]any{})
	data := []byte("racing")
	bid := e.upload("r", "a", "text/plain", data)
	hook = func() {
		e.clock.Advance(25 * time.Hour)
		if n, err := e.e.SweepBlobs(context.Background()); err != nil || n != 1 {
			t.Errorf("sweep %d %v", n, err)
		}
	}
	expectCode(t, e.write("PATCH", "r", "a", "", addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")})), 422, "blob")
	if s := e.blobStats(); s.Attached != 0 || s.Bytes != 0 {
		t.Fatalf("stats %+v", s)
	}
}

// §7.5: a dry run reports unavailable blobs as blob failures.
func TestBlobDryRun(t *testing.T) {
	e := newEnv(t, withBlobTuning)
	e.mkNS("d", map[string]any{})
	data := []byte("dry")
	bid := e.upload("d", "ok", "text/plain", data)
	missing := blobID("text/plain", "", []byte("missing"))
	body := map[string]any{"items": []any{
		map[string]any{"resource": "ok", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), "")})}},
		map[string]any{"resource": "bad", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"b": ref(missing, "text/plain", 7, "")})}},
	}}
	r := e.do(req{method: "POST", path: "/ns/d/batch?dry-run=1", author: "alice", body: body})
	expect(t, r, 200)
	items := r.Obj()["items"].([]any)
	ok, bad := items[0].(map[string]any), items[1].(map[string]any)
	if ok["status"] != 200.0 || bad["status"] != 422.0 || bad["code"] != "blob" {
		t.Fatalf("report %s", r.Body)
	}
	if s := e.blobStats(); s.Attached != 0 || s.Pending != 1 {
		t.Fatalf("a dry run attaches nothing: %+v", s)
	}
}
