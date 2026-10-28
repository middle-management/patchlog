package server

import (
	"testing"
)

// §7.4, §6.2 (v0.74, CORE-1): a gestures after not of the form
// {resource}/{id} is a request-shape 400, answered before the namespace
// is looked up, so ahead of the 401 a private namespace gives an
// anonymous caller; an after naming an entry of a purged resource is 404.
func TestV074GesturesAfter(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	e.mkNS("pub", map[string]any{"read": "public"})
	for _, bad := range []string{"nonsense", "a/nope", "A/" + gA, "/x", "a/"} {
		expectCode(t, e.get("/ns/pub/gestures/"+gA+"?after="+bad), 400, "bad_input")
		expectCode(t, e.get("/ns/sec/gestures/"+gA+"?after="+bad), 400, "bad_input")
	}
	// Still 401 for a well-formed after without a grant.
	expect(t, e.get("/ns/sec/gestures/"+gA+"?after=r/"+hashID(t, "", []byte("x"))), 401)

	wr := func(name, parent string, patches []any) string {
		q := req{method: "PATCH", path: "/r/sec/" + name, ifMatch: parent, bearer: f.adminG, body: patches, hdr: map[string]string{"Gesture": gA}}
		if parent == "" {
			q.ifNoneMatch = "*"
		}
		r := e.do(q)
		expect(t, r, 201)
		return etagOf(r)
	}
	r0 := wr("r", "", addRoot(map[string]any{"n": 0.0}))
	wr("r", r0, ops(op("replace", "/n", 1.0)))
	wr("s", "", addRoot(map[string]any{}))
	expect(t, e.get("/ns/sec/gestures/"+gA+"?after=r/"+r0, f.adminG), 200)
	expect(t, e.purge("sec", "r", e.head("sec", "r", f.adminG), f.adminG), 204)
	expectCode(t, e.get("/ns/sec/gestures/"+gA+"?after=r/"+r0, f.adminG), 404, "not_found")
}

// §7.8 Copying (v0.74, CORE-5): after the copy's 400s comes a sent
// precondition's 428, before any body is read, so ahead of a different
// bid's 422 and of the source check's 404.
func TestV074BlobCopyPreconditionFirst(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil, withBlobTuning)
	e := f.tenv
	data := []byte("copy order")
	bid := blobID("text/plain", "", data)
	expect(t, e.putBlobAs("sec", "a", bid, "text/plain", "", data, f.adminG), 201)
	e.create("sec", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")}, f.adminG)
	put := func(path string, hdr map[string]string) *resp {
		return e.do(req{method: "PUT", path: path, bearer: f.issuerG, hdr: hdr})
	}
	// A source the caller can't read (another namespace it holds no
	// grant for), or none at all: 428 with a precondition, else 404.
	e.mkNS("other", map[string]any{"read": "grant"})
	for _, src := range []string{blobPath("other", "x", bid), blobPath("sec", "none", bid)} {
		expectCode(t, put(blobPath("sec", "c", bid), map[string]string{"Blob-From": src, "If-None-Match": "*"}), 428, "precondition_required")
		expectCode(t, put(blobPath("sec", "c", bid), map[string]string{"Blob-From": src}), 404, "not_found")
	}
	// A different bid: 428 with a precondition, 422 without.
	other := blobID("text/plain", "", []byte("other"))
	from := blobPath("sec", "a", bid)
	expectCode(t, put(blobPath("sec", "c", other), map[string]string{"Blob-From": from, "If-Match": `"` + bid + `"`}), 428, "precondition_required")
	expectCode(t, put(blobPath("sec", "c", other), map[string]string{"Blob-From": from}), 422, "blob")
	// The 400s still come first.
	expectCode(t, put(blobPath("sec", "c", bid), map[string]string{"Blob-From": "/nope", "If-None-Match": "*"}), 400, "bad_input")
	expect(t, put(blobPath("sec", "c", bid), map[string]string{"Blob-From": from}), 201)
}

// §8.5 (v0.74, CORE-4): in an unsealed purged namespace, events and
// long-poll from the purge-ns entry are 410 purged with head; earlier
// since values and the immutable range from it are served as before.
func TestV074PurgedStreamFromPurgeNS(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("n", map[string]any{"read": "public"})
	e.create("n", "a", map[string]any{})
	before := e.nsHead("n")
	p := e.nsPurge("n")
	expectPurged(t, e.get("/ns/n/events?since="+p), p)
	expectPurged(t, e.do(req{method: "GET", path: "/ns/n/events", hdr: map[string]string{"Last-Event-ID": p}}), p)
	expectPurged(t, e.get("/ns/n/log?since="+p+"&live=long-poll"), p)
	// A long-poll from before the purge gets its entries at once.
	r := e.get("/ns/n/log?since=" + before + "&live=long-poll")
	expect(t, r, 200)
	if es := r.Arr(); len(es) != 2 || es[1].(map[string]any)["kind"] != "purge-ns" {
		t.Fatalf("long-poll from before the purge: %s", r.Body)
	}
	// The immutable range from it is an empty page.
	r = e.get("/ns/n/rev/" + p + "/log?since=" + p)
	expect(t, r, 200)
	if len(r.Arr()) != 0 {
		t.Fatalf("range from the purge-ns entry: %s", r.Body)
	}
}
