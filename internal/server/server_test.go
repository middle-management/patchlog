package server

import (
	"strings"
	"testing"
	"time"
)

// §3.3–§3.5, invariant "Verifiable": every id can be recomputed from the logs.
func TestIdsVerifiable(t *testing.T) {
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	r1 := e.create("docs", "a", map[string]any{"title": "x"})
	r2 := e.appendRev("docs", "a", r1, ops(op("replace", "/title", "y")))
	tomb := e.del("docs", "a", r2)
	r3 := e.appendRev("docs", "a", tomb, []any{}) // restore unchanged

	lg := e.get("/r/docs/a/rev/" + r3 + "/log")
	expect(t, lg, 200)
	entries := lg.Arr()
	if len(entries) != 4 {
		t.Fatalf("log has %d entries: %s", len(entries), lg.Body)
	}
	parent := ""
	for i, x := range entries {
		m := x.(map[string]any)
		if p, _ := m["parent"].(string); p != parent {
			t.Fatalf("entry %d: parent %q, want %q", i, p, parent)
		}
		var want string
		switch m["kind"] {
		case "rev":
			want = hashID(t, parent, canonical(m["patches"]))
		case "tombstone":
			want = hashID(t, parent, []byte("tombstone"))
			if _, has := m["patches"]; has {
				t.Fatalf("tombstone entry carries patches")
			}
		default:
			t.Fatalf("unknown kind %v", m["kind"])
		}
		if m["id"] != want {
			t.Fatalf("entry %d: id %v, recomputed %s", i, m["id"], want)
		}
		if m["author"] != "alice" || m["created"] == nil {
			t.Fatalf("entry %d lacks author/created: %v", i, m)
		}
		parent = want
	}
	if parent != r3 {
		t.Fatalf("last id %s, want %s", parent, r3)
	}

	// Namespace chain: recompute every ns_id from the stored entries.
	head := e.nsHead("docs")
	nl := e.get("/ns/docs/rev/" + head + "/log")
	expect(t, nl, 200)
	prev := ""
	var kinds []string
	for i, x := range nl.Arr() {
		m := x.(map[string]any)
		entry := map[string]any{}
		for k, v := range m {
			switch k {
			case "id", "prev", "author", "created", "grant":
			default:
				entry[k] = v
			}
		}
		if p, _ := m["prev"].(string); p != prev {
			t.Fatalf("ns entry %d: prev %q, want %q", i, p, prev)
		}
		want := hashID(t, prev, canonical(entry))
		if m["id"] != want {
			t.Fatalf("ns entry %d: id %v, recomputed %s (%v)", i, m["id"], want, entry)
		}
		prev = want
		kinds = append(kinds, m["kind"].(string))
	}
	if prev != head {
		t.Fatalf("chain ends at %s, head is %s", prev, head)
	}
	if got := strings.Join(kinds, ","); got != "config,head,head,tombstone,head" {
		t.Fatalf("ns kinds %s", got)
	}
	// The config revision id: the genesis of the namespace document chain.
	cfg := e.configID("docs")
	if want := hashID(t, "", canonical(addRoot(map[string]any{"read": "public"}))); cfg != want {
		t.Fatalf("config id %s, want %s", cfg, want)
	}
}

// §3.1: the server stores, serves and hashes canonical(patches).
func TestCanonicalStorage(t *testing.T) {
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	raw := `[ {"value": {"z": 1.0, "a": "é", "n": 1e2}, "path": "", "op": "add"} ]`
	r := e.do(req{method: "PATCH", path: "/r/docs/a", ifNoneMatch: "*", raw: raw, author: "alice"})
	expect(t, r, 201)
	id := etagOf(r)
	want := `[{"op":"add","path":"","value":{"a":"é","n":100,"z":1}}]`
	if got := hashID(t, "", []byte(want)); got != id {
		t.Fatalf("id %s is not the hash of the canonical patches (%s)", id, got)
	}
	lg := e.get("/r/docs/a/rev/" + id + "/log")
	expect(t, lg, 200)
	if !strings.Contains(string(lg.Body), `"patches":`+want) {
		t.Fatalf("log does not carry canonical patches: %s", lg.Body)
	}
	d := e.get("/r/docs/a/rev/" + id)
	if string(d.Body) != `{"a":"é","n":100,"z":1}` {
		t.Fatalf("document %s", d.Body)
	}
	// The write response carries the entry too.
	if !strings.Contains(r.String(), want) {
		t.Fatalf("write response %s", r.Body)
	}
}

// §3.1: I-JSON rejections.
func TestIJSONRejected(t *testing.T) {
	e := newEnv(t)
	e.mkNS("docs", map[string]any{})
	for name, raw := range map[string]string{
		"duplicate key":  `[{"op":"add","path":"","value":{"a":1,"a":2}}]`,
		"lone surrogate": `[{"op":"add","path":"","value":{"a":"\ud800"}}]`,
		"big int":        `[{"op":"add","path":"","value":{"a":9007199254740993}}]`,
		"big int neg":    `[{"op":"add","path":"","value":{"a":-9007199254740992}}]`,
		"non-finite":     `[{"op":"add","path":"","value":{"a":1e400}}]`,
		"not json":       `[{"op":"add",`,
	} {
		r := e.do(req{method: "PATCH", path: "/r/docs/a", ifNoneMatch: "*", raw: raw, author: "alice"})
		if r.Code != 400 || r.Str("code") != "bad_input" {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	// Largest safe integer is fine.
	r := e.do(req{method: "PATCH", path: "/r/docs/a", ifNoneMatch: "*", raw: `[{"op":"add","path":"","value":{"a":9007199254740991}}]`, author: "alice"})
	expect(t, r, 201)
	// Batches and namespace writes are I-JSON too.
	r = e.do(req{method: "POST", path: "/ns/docs/batch", raw: `{"items":[],"items":[]}`, author: "alice"})
	expectCode(t, r, 400, "bad_input")
	r = e.do(req{method: "PATCH", path: "/ns/docs", ifMatch: e.configID("docs"), raw: `[{"op":"add","path":"/x","value":"\udc00"}]`})
	expectCode(t, r, 400, "bad_input")
}

// §3.6: name grammar and canonical URLs.
func TestNamesAndURLs(t *testing.T) {
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	e.create("docs", "a.b-c_d", map[string]any{})

	for _, ns := range []string{"Docs", "-x", "a.b", strings.Repeat("a", 65)} {
		r := e.do(req{method: "PATCH", path: "/ns/" + ns, ifNoneMatch: "*", body: addRoot(map[string]any{})})
		if r.Code != 400 {
			t.Errorf("namespace %q: %d %s", ns, r.Code, r.Body)
		}
	}
	for _, name := range []string{"A", ".x", "_x", strings.Repeat("a", 129), "a~b"} {
		r := e.write("PATCH", "docs", name, "", addRoot(map[string]any{}))
		if r.Code != 400 {
			t.Errorf("resource %q: %d %s", name, r.Code, r.Body)
		}
	}
	// Longest valid names.
	if r := e.write("PATCH", "docs", strings.Repeat("a", 128), "", addRoot(map[string]any{})); r.Code != 201 {
		t.Errorf("128-char name: %d", r.Code)
	}
	// Percent-encoded and dot-segment URLs.
	for _, p := range []string{
		"/r/docs/a%2Eb-c_d",
		"/r/%64ocs/a.b-c_d",
		"/r/docs/./a.b-c_d",
		"/r/docs/../docs/a.b-c_d",
		"/r/docs//a.b-c_d",
		"/r/docs/a.b-c_d/.",
		"/r/docs/%61",
	} {
		if code := e.rawGet(p); code != 400 {
			t.Errorf("%s: %d, want 400", p, code)
		}
	}
	if code := e.rawGet("/r/docs/a.b-c_d"); code != 302 {
		t.Errorf("canonical URL: %d", code)
	}
	// A dot as a whole name segment is not a valid resource name either.
	if code := e.rawGet("/r/docs/.."); code != 400 {
		t.Errorf("/r/docs/..: %d", code)
	}
}

// §7.1 reads: head pointer states, revisions, logs.
func TestReads(t *testing.T) {
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	r1 := e.create("docs", "a", map[string]any{"v": 1.0})
	r2 := e.appendRev("docs", "a", r1, ops(op("replace", "/v", 2.0)))

	// 302 head pointer.
	h := e.get("/r/docs/a")
	expect(t, h, 302)
	if h.H.Get("Location") != "/r/docs/a/rev/"+r2 || h.H.Get("ETag") != `"`+r2+`"` {
		t.Fatalf("head headers %v", h.H)
	}
	if cc := h.H.Get("Cache-Control"); cc != "public, max-age=0, s-maxage=1, stale-while-revalidate=5" {
		t.Fatalf("head Cache-Control %q", cc)
	}
	if tag := h.H.Get("Cache-Tag"); tag != "ns:docs,r:docs/a" {
		t.Fatalf("head Cache-Tag %q", tag)
	}
	// HEAD works like GET without a body.
	hh := e.do(req{method: "HEAD", path: "/r/docs/a"})
	if hh.Code != 302 || len(hh.Body) != 0 || hh.H.Get("ETag") != `"`+r2+`"` {
		t.Fatalf("HEAD: %d %v", hh.Code, hh.H)
	}

	// Revision 200 with ETag, X-Revision, immutable caching; 304.
	rv := e.get("/r/docs/a/rev/" + r1)
	expect(t, rv, 200)
	if rv.String() != `{"v":1}` || rv.H.Get("X-Revision") != r1 || rv.H.Get("ETag") != `"`+r1+`"` {
		t.Fatalf("rev: %s %v", rv.Body, rv.H)
	}
	if cc := rv.H.Get("Cache-Control"); cc != "public, max-age=86400, s-maxage=31536000, immutable" {
		t.Fatalf("rev Cache-Control %q", cc)
	}
	if tag := rv.H.Get("Cache-Tag"); tag != "ns:docs,r:docs/a" {
		t.Fatalf("rev Cache-Tag %q", tag)
	}
	nm := e.do(req{method: "GET", path: "/r/docs/a/rev/" + r1, hdr: map[string]string{"If-None-Match": `"` + r1 + `"`}})
	expect(t, nm, 304)

	// Unknown id 404 short; unknown resource 404 short.
	unknown := hashID(t, "", []byte("nope"))
	u := e.get("/r/docs/a/rev/" + unknown)
	expect(t, u, 404)
	if cc := u.H.Get("Cache-Control"); cc != "public, max-age=5" {
		t.Fatalf("404 Cache-Control %q", cc)
	}
	nf := e.get("/r/docs/missing")
	expectCode(t, nf, 404, "not_found")
	if cc := nf.H.Get("Cache-Control"); cc != "public, max-age=5" {
		t.Fatalf("404 head Cache-Control %q", cc)
	}
	// An id of another resource is unknown here.
	other := e.create("docs", "b", map[string]any{"w": true})
	expect(t, e.get("/r/docs/a/rev/"+other), 404)
	// Unknown namespace.
	expect(t, e.get("/r/nope/a"), 404)

	// Logs: since ranges.
	lg := e.get("/r/docs/a/rev/" + r2 + "/log?since=" + r1)
	expect(t, lg, 200)
	if a := lg.Arr(); len(a) != 1 || a[0].(map[string]any)["id"] != r2 {
		t.Fatalf("since range: %s", lg.Body)
	}
	lg = e.get("/r/docs/a/rev/" + r1 + "/log")
	if a := lg.Arr(); len(a) != 1 || a[0].(map[string]any)["id"] != r1 {
		t.Fatalf("to r1: %s", lg.Body)
	}
	lg = e.get("/r/docs/a/rev/" + r2 + "/log?since=" + r2)
	expect(t, lg, 200)
	if len(lg.Arr()) != 0 {
		t.Fatalf("since=id: %s", lg.Body)
	}
	if cc := lg.H.Get("Cache-Control"); cc != "public, max-age=86400, s-maxage=31536000, immutable" {
		t.Fatalf("log Cache-Control %q", cc)
	}
	// since not an ancestor of id: 404 (a descendant, an unknown id, another resource's id).
	expect(t, e.get("/r/docs/a/rev/"+r1+"/log?since="+r2), 404)
	expect(t, e.get("/r/docs/a/rev/"+r2+"/log?since="+unknown), 404)
	expect(t, e.get("/r/docs/a/rev/"+r2+"/log?since="+other), 404)

	// Tombstoned: 410 {tombstone, last} with ETag; history stays readable.
	tomb := e.del("docs", "a", r2)
	g := e.get("/r/docs/a")
	expectCode(t, g, 410, "gone")
	if g.Str("tombstone") != tomb || g.Str("last") != r2 || g.H.Get("ETag") != `"`+tomb+`"` {
		t.Fatalf("tombstoned head: %s %v", g.Body, g.H)
	}
	if cc := g.H.Get("Cache-Control"); cc != "public, max-age=0, s-maxage=1, stale-while-revalidate=5" {
		t.Fatalf("tombstone head Cache-Control %q", cc)
	}
	expect(t, e.get("/r/docs/a/rev/"+r2), 200)
	tr := e.get("/r/docs/a/rev/" + tomb)
	expect(t, tr, 410)
	if cc := tr.H.Get("Cache-Control"); cc != "public, max-age=86400, s-maxage=31536000, immutable" {
		t.Fatalf("tombstone id 410 must be immutable, got %q", cc)
	}
	lg = e.get("/r/docs/a/rev/" + tomb + "/log?since=" + r2)
	if a := lg.Arr(); len(a) != 1 || a[0].(map[string]any)["kind"] != "tombstone" {
		t.Fatalf("log to tombstone: %s", lg.Body)
	}
}

// §7.2 writes: statuses, preconditions, bodies and headers.
func TestWrites(t *testing.T) {
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})

	// 428 without a precondition.
	r := e.do(req{method: "PATCH", path: "/r/docs/a", body: addRoot(map[string]any{}), author: "alice"})
	expectCode(t, r, 428, "precondition_required")
	r = e.do(req{method: "DELETE", path: "/r/docs/a", author: "alice"})
	expectCode(t, r, 428, "precondition_required")

	// 415 for other content types.
	r = e.do(req{method: "PATCH", path: "/r/docs/a", ifNoneMatch: "*", ct: "application/json", body: addRoot(map[string]any{}), author: "alice"})
	expect(t, r, 415)
	r = e.do(req{method: "PATCH", path: "/r/docs/a", ifNoneMatch: "*", ct: "application/merge-patch+json", body: map[string]any{}, author: "alice"})
	expect(t, r, 415)
	// Parameters on the media type are fine.
	r = e.do(req{method: "PATCH", path: "/r/docs/p", ifNoneMatch: "*", ct: "application/json-patch+json; charset=utf-8", body: addRoot(map[string]any{}), author: "alice"})
	expect(t, r, 201)

	// Create: 201 with Location, ETag, X-Namespace-Revision, no-store.
	r = e.write("PATCH", "docs", "a", "", addRoot(map[string]any{"n": 1.0}))
	expect(t, r, 201)
	id1 := etagOf(r)
	if r.H.Get("Location") != "/r/docs/a/rev/"+id1 || r.H.Get("Cache-Control") != "no-store" {
		t.Fatalf("create headers %v", r.H)
	}
	nsid := r.H.Get("X-Namespace-Revision")
	if nsid == "" || nsid != e.nsHead("docs") {
		t.Fatalf("X-Namespace-Revision %q, head %q", nsid, e.nsHead("docs"))
	}
	// Create on an existing resource: 412 {head}.
	r = e.write("PATCH", "docs", "a", "", addRoot(map[string]any{"n": 2.0}))
	expectCode(t, r, 412, "stale")
	if r.Str("head") != id1 {
		t.Fatalf("412 body %s", r.Body)
	}
	// Append: 201; stale parent 412 {head}.
	id2 := e.appendRev("docs", "a", id1, ops(op("replace", "/n", 2.0)))
	r = e.write("PATCH", "docs", "a", id1, ops(op("replace", "/n", 3.0)))
	expectCode(t, r, 412, "stale")
	if r.Str("head") != id2 {
		t.Fatalf("412 head %s", r.Body)
	}
	// Append to a missing resource: 412.
	r = e.write("PATCH", "docs", "missing", id1, ops(op("replace", "/n", 3.0)))
	expect(t, r, 412)
	// 422: failing test op, bad patch.
	r = e.write("PATCH", "docs", "a", id2, ops(op("test", "/n", 1.0), op("replace", "/n", 9.0)))
	expectCode(t, r, 422, "invalid")
	r = e.write("PATCH", "docs", "a", id2, ops(op("remove", "/nope")))
	expectCode(t, r, 422, "invalid")
	r = e.write("PATCH", "docs", "a", id2, []any{map[string]any{"op": "frob", "path": ""}})
	expectCode(t, r, 422, "invalid")
	// Malformed If-Match.
	r = e.do(req{method: "PATCH", path: "/r/docs/a", hdr: map[string]string{"If-Match": "abc"}, body: []any{}, author: "alice"})
	expect(t, r, 400)

	// Delete: 200 {tombstone}; stale 412 {head}; already tombstoned 410.
	r = e.write("DELETE", "docs", "a", id1, nil)
	expectCode(t, r, 412, "stale")
	if r.Str("head") != id2 {
		t.Fatalf("delete 412 %s", r.Body)
	}
	r = e.write("DELETE", "docs", "a", id2, nil)
	expect(t, r, 200)
	tomb := r.Str("tombstone")
	if tomb != hashID(t, id2, []byte("tombstone")) || r.H.Get("X-Namespace-Revision") == "" || r.H.Get("Cache-Control") != "no-store" {
		t.Fatalf("delete %s %v", r.Body, r.H)
	}
	r = e.write("DELETE", "docs", "a", tomb, nil)
	expectCode(t, r, 410, "gone")
	// Append on a tombstoned resource with the old head: 410.
	r = e.write("PATCH", "docs", "a", id2, ops(op("replace", "/n", 3.0)))
	expectCode(t, r, 410, "gone")
	// Create on a tombstoned resource: 412 {head: tombstone}.
	r = e.write("PATCH", "docs", "a", "", addRoot(map[string]any{}))
	expectCode(t, r, 412, "stale")
	if r.Str("head") != tomb {
		t.Fatalf("create on tombstone: %s", r.Body)
	}
	// Restore with patches: 201; applies to the last live document.
	r3 := e.appendRev("docs", "a", tomb, ops(op("add", "/restored", true)))
	if d := e.doc("docs", "a"); d["n"] != 2.0 || d["restored"] != true {
		t.Fatalf("restored doc %v", d)
	}
	// Purged: 410 for writes.
	r = e.do(req{method: "POST", path: "/r/docs/a/purge", ifMatch: r3, author: "alice"})
	expect(t, r, 204)
	r = e.write("PATCH", "docs", "a", r3, ops(op("replace", "/n", 3.0)))
	expectCode(t, r, 410, "gone")
	r = e.write("PATCH", "docs", "a", "", addRoot(map[string]any{}))
	expectCode(t, r, 410, "gone")
	r = e.write("DELETE", "docs", "a", r3, nil)
	expectCode(t, r, 410, "gone")
	// Unknown namespace.
	r = e.write("PATCH", "nope", "a", "", addRoot(map[string]any{}))
	expect(t, r, 404)
}

// §7.2 idempotent retry.
func TestIdempotentRetry(t *testing.T) {
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	genesis := addRoot(map[string]any{"n": 1.0})
	id1 := e.create("docs", "a", map[string]any{"n": 1.0}, "alice")
	createNS := e.nsHead("docs")

	// Create retried by the same principal: 200 with the same id and ns entry.
	r := e.write("PATCH", "docs", "a", "", genesis, "alice")
	expect(t, r, 200)
	if etagOf(r) != id1 || r.H.Get("X-Namespace-Revision") != createNS {
		t.Fatalf("create retry: %v %s", r.H, r.Body)
	}
	// Another principal gets 412.
	r = e.write("PATCH", "docs", "a", "", genesis, "bob")
	expectCode(t, r, 412, "stale")

	id2 := e.appendRev("docs", "a", id1, ops(op("replace", "/n", 2.0)), "alice")
	// Others write since.
	id3 := e.appendRev("docs", "a", id2, ops(op("replace", "/n", 3.0)), "bob")
	// Alice's retry of her append still gets 200 with that entry.
	r = e.write("PATCH", "docs", "a", id1, ops(op("replace", "/n", 2.0)), "alice")
	expect(t, r, 200)
	if etagOf(r) != id2 {
		t.Fatalf("append retry id %s, want %s", etagOf(r), id2)
	}
	// Bob sending Alice's patches: 412.
	r = e.write("PATCH", "docs", "a", id1, ops(op("replace", "/n", 2.0)), "bob")
	expectCode(t, r, 412, "stale")
	if r.Str("head") != id3 {
		t.Fatalf("412 %s", r.Body)
	}
	// Delete retry.
	tomb := e.del("docs", "a", id3, "alice")
	r = e.write("DELETE", "docs", "a", id3, nil, "alice")
	expect(t, r, 200)
	if r.Str("tombstone") != tomb {
		t.Fatalf("delete retry %s", r.Body)
	}
	r = e.write("DELETE", "docs", "a", id3, nil, "bob")
	expect(t, r, 410)
	// Nothing was written by the retries.
	lg := e.get("/ns/docs/rev/" + e.nsHead("docs") + "/log")
	if n := len(lg.Arr()); n != 5 {
		t.Fatalf("ns log has %d entries, want 5: %s", n, lg.Body)
	}
	// Retry after the namespace is frozen: still 200 (the retry comes before 409).
	id4 := e.appendRev("docs", "a", tomb, []any{}, "alice")
	expect(t, e.patchNS("docs", ops(op("add", "/frozen", true)), ""), 201)
	r = e.write("PATCH", "docs", "a", tomb, []any{}, "alice")
	expect(t, r, 200)
	if etagOf(r) != id4 {
		t.Fatalf("frozen retry %s", r.Body)
	}
	r = e.write("PATCH", "docs", "a", id4, ops(op("add", "/x", 1.0)), "alice")
	expectCode(t, r, 409, "frozen")
}

// Invariant "Append-only" / "Linear": a head only moves to a child; history
// is never rewritten, and every mutating request writes one ns entry.
func TestInvariantsLinearAndOrdered(t *testing.T) {
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	id1 := e.create("docs", "a", map[string]any{"n": 0.0})
	before := e.get("/r/docs/a/rev/" + id1)
	head := id1
	for i := 1; i <= 5; i++ {
		head = e.appendRev("docs", "a", head, ops(op("replace", "/n", float64(i))))
	}
	// Two writers racing on the same parent: exactly one wins.
	a := e.write("PATCH", "docs", "a", head, ops(op("add", "/w", "a")), "alice")
	b := e.write("PATCH", "docs", "a", head, ops(op("add", "/w", "b")), "bob")
	if a.Code != 201 || b.Code != 412 {
		t.Fatalf("race: %d %d", a.Code, b.Code)
	}
	// Old revisions still serve the same bytes.
	after := e.get("/r/docs/a/rev/" + id1)
	if string(before.Body) != string(after.Body) {
		t.Fatal("history changed")
	}
	lg := e.get("/r/docs/a/rev/" + etagOf(a) + "/log")
	if n := len(lg.Arr()); n != 7 {
		t.Fatalf("log length %d", n)
	}
	nl := e.get("/ns/docs/rev/" + e.nsHead("docs") + "/log")
	if n := len(nl.Arr()); n != 8 { // config + 7 writes
		t.Fatalf("ns log length %d: %s", n, nl.Body)
	}
	// Failed writes write nothing.
	e.write("PATCH", "docs", "a", id1, []any{})
	e.write("PATCH", "docs", "a", etagOf(a), ops(op("remove", "/missing")))
	if n := len(e.get("/ns/docs/rev/" + e.nsHead("docs") + "/log").Arr()); n != 8 {
		t.Fatalf("failed writes appended entries: %d", n)
	}
}

// §9 caching of private namespaces.
func TestPrivateCaching(t *testing.T) {
	e := newEnv(t)
	e.mkNS("priv", map[string]any{"read": "grant"})
	id := e.create("priv", "a", map[string]any{})
	r := e.get("/r/priv/a/rev/" + id)
	expect(t, r, 200)
	if cc := r.H.Get("Cache-Control"); !strings.HasPrefix(cc, "private") {
		t.Fatalf("private Cache-Control %q", cc)
	}
	// No verifying edge (the default): no shared cache stores it.
	if cc, sc := r.H.Get("CDN-Cache-Control"), r.H.Get("Surrogate-Control"); cc != "no-store" || sc != "no-store" {
		t.Fatalf("CDN-Cache-Control %q, Surrogate-Control %q", cc, sc)
	}
	h := e.get("/r/priv/a")
	if cc := h.H.Get("Cache-Control"); !strings.HasPrefix(cc, "private") {
		t.Fatalf("private head Cache-Control %q", cc)
	}
}

// §6.6 limits: patch set size, operations, depth, and lowering via /limits.
func TestLimits(t *testing.T) {
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public", "limits": map[string]any{"patchSetSize": 200.0, "opsPerSet": 3.0, "nestingDepth": 3.0}})
	id := e.create("docs", "a", map[string]any{"a": map[string]any{"b": 1.0}})
	r := e.write("PATCH", "docs", "a", id, ops(op("add", "/big", strings.Repeat("x", 300))))
	expectCode(t, r, 413, "limit")
	r = e.write("PATCH", "docs", "a", id, ops(op("add", "/1", 1.0), op("add", "/2", 1.0), op("add", "/3", 1.0), op("add", "/4", 1.0)))
	expectCode(t, r, 422, "limit")
	r = e.write("PATCH", "docs", "a", id, ops(op("add", "/a/b", map[string]any{"c": map[string]any{"d": 1.0}})))
	expectCode(t, r, 422, "limit")
	e.appendRev("docs", "a", id, ops(op("add", "/1", 1.0), op("add", "/2", 1.0), op("add", "/3", 1.0)))

	// Raising above the deployment maximum is refused; lowering works.
	r = e.patchNS("docs", ops(op("replace", "/limits/opsPerSet", 5000.0)), "")
	expectCode(t, r, 422, "limit")
	r = e.patchNS("docs", ops(op("replace", "/limits/opsPerSet", 1.0)), "")
	expect(t, r, 201)
	r = e.write("PATCH", "docs", "a", e.head("docs", "a"), ops(op("add", "/x", 1.0), op("add", "/y", 1.0)))
	expectCode(t, r, 422, "limit")
	// Unknown limits and a retry window outside the deployment range.
	expectCode(t, e.patchNS("docs", ops(op("add", "/limits/frobs", 1.0)), ""), 422, "invalid")
	expectCode(t, e.patchNS("docs", ops(op("add", "/limits/retryWindow", "PT1M")), ""), 422, "limit")
}

// §6.6 rate limits: 429 with Retry-After, code rate and the limit hit.
func TestRateLimits(t *testing.T) {
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public", "limits": map[string]any{
		"ratePerResource":  map[string]any{"rate": 1.0, "burst": 2.0},
		"ratePerNamespace": map[string]any{"rate": 1.0, "burst": 4.0},
	}})
	h := e.create("docs", "a", map[string]any{"n": 0.0})
	h = e.appendRev("docs", "a", h, ops(op("replace", "/n", 1.0)))
	r := e.write("PATCH", "docs", "a", h, ops(op("replace", "/n", 2.0)))
	expectCode(t, r, 429, "rate")
	if r.H.Get("Retry-After") == "" || r.Obj()["limit"] == nil {
		t.Fatalf("429 without Retry-After or limit: %v %s", r.H, r.Body)
	}
	// Another principal has its own per-resource bucket.
	h = e.appendRev("docs", "a", h, ops(op("replace", "/n", 2.0)), "bob")
	// The namespace bucket (4) is shared: 3 used; one more, then 429.
	e.create("docs", "b", map[string]any{}, "carol")
	r = e.write("PATCH", "docs", "c", "", addRoot(map[string]any{}), "dave")
	expectCode(t, r, 429, "rate")
	// Unauthorised or invalid requests don't consume... the precondition
	// failure (after step 1) does, so only check refill.
	e.clock.Advance(5 * time.Second)
	e.appendRev("docs", "a", h, ops(op("replace", "/n", 3.0)))
	// Freezing is exempt, and purges are exempt.
	for i := 0; i < 5; i++ {
		e.write("PATCH", "docs", "zz", "", addRoot(map[string]any{}), "x")
	}
	expect(t, e.patchNS("docs", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.do(req{method: "POST", path: "/r/docs/b/purge", ifMatch: e.head("docs", "b"), author: "carol"}), 204)
}

// Invariant "Configuration in force": a write is checked against the
// configuration at the head when it is inserted; history is never re-evaluated.
func TestInvariantConfigurationInForce(t *testing.T) {
	e := newEnv(t)
	cfg0 := e.mkNS("docs", map[string]any{"read": "public"})
	h := e.create("docs", "a", map[string]any{"draft": true})
	// The namespace revision of the create reports the configuration in force then.
	createNS := e.nsHead("docs")
	rule := map[string]any{"op": "test", "path": "/doc/draft", "exists": false}
	expect(t, e.patchNS("docs", ops(op("add", "/rules", []any{map[string]any{
		"if": []any{map[string]any{"op": "test", "path": "/action", "value": "append"}}, "then": []any{rule}}})), ""), 201)
	expectCode(t, e.write("PATCH", "docs", "a", h, ops(op("add", "/x", 1.0))), 422, "rule")
	h = e.appendRev("docs", "a", h, ops(op("remove", "/draft")))
	// The earlier revision is still served, and the ns revision before the
	// config change still reports the old configuration.
	expect(t, e.get("/r/docs/a/rev/"+h), 200)
	if c := e.get("/ns/docs/rev/" + createNS).H.Get("X-Config-Revision"); c != cfg0 {
		t.Fatalf("config in force at the create: %s, want %s", c, cfg0)
	}
	// Removing the rule applies at once.
	expect(t, e.patchNS("docs", ops(op("remove", "/rules")), ""), 201)
	e.appendRev("docs", "a", h, ops(op("add", "/draft", true)))
}

// §6.6, §7.5: a batch whose config change went stale draws its tokens
// before the whole-batch replay answers it (§7.2), like every request that
// passed step 1; a drained bucket is 429, not a free 200.
func TestReviewRetryAfterStaleConfigDraws(t *testing.T) {
	e := newEnv(t)
	e.mkNS("m", map[string]any{"limits": map[string]any{
		"ratePerPrincipal": map[string]any{"rate": 1, "burst": 1}}})
	cfg := e.configID("m")
	batch := map[string]any{
		"config": map[string]any{"ifMatch": cfg, "patches": ops(op("add", "/x-a", 1.0))},
		"items": []any{
			map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"b": true})}}}}
	// The first submit lands the batch.
	expect(t, e.batchReq("m", batch, "alice"), 201)
	// Its retry arrives after the config moved: the config precondition is
	// stale, the whole-batch replay matches, and the answer is 200 — having
	// consumed the principal's token, which the bucket had refilled.
	e.clock.Advance(5 * time.Second)
	e.patchNS("m", ops(op("add", "/x-other", 1.0)), "admin")
	expect(t, e.batchReq("m", batch, "alice"), 200)
	// A copy right after it finds the bucket drained: 429. Without the
	// draw, both retries would be token-free 200s.
	expectCode(t, e.batchReq("m", batch, "alice"), 429, "rate")
}

// §6.6 (v0.40): a batch's config change costs a token from the principal
// and namespace buckets unless it is exempt, as a config write does, so a
// config-only batch isn't free; under a * key it costs nothing.
func TestBatchConfigChangeDrawsToken(t *testing.T) {
	f := newAuthFixture(t, map[string]any{"limits": map[string]any{
		"ratePerPrincipal": map[string]any{"rate": 0.001, "burst": 1}}})
	e := f.tenv
	change := func(who, member string) *resp {
		return e.batchReq("sec", map[string]any{"config": map[string]any{
			"ifMatch": e.configID("sec", f.adminG), "patches": ops(op("add", "/"+member, 1.0))}}, who)
	}
	expect(t, change(f.issuerG, "x-a"), 201)
	expectCode(t, change(f.issuerG, "x-b"), 429, "rate")
	// Exempt under a * key, however many.
	for _, m := range []string{"x-c", "x-d", "x-e"} {
		expect(t, change(f.adminG, m), 201)
	}
}
