package server

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
)

// Serving after a raise to e2e (P35, Addendum E Levels).

// p35Sealed seals patches for ns/name on parent under kid, declaring
// blobs.
func p35Sealed(t *testing.T, k []byte, kid, ns, name, parent string, patches []any, blobs ...string) string {
	t.Helper()
	b, err := seal.SealPatchSet(k, kid, ns, name, parent, jsonv.FromGo(patches))
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) > 0 {
		if b, err = seal.WithBlobs(b, blobs); err != nil {
			t.Fatal(err)
		}
	}
	return string(b)
}

// p35Head is the namespace head of ns, from the /ns/{ns} redirect.
func (e *tenv) p35Head(ns string) string {
	e.t.Helper()
	r := e.get("/ns/" + ns)
	expect(e.t, r, 302)
	loc := r.H.Get("Location")
	return loc[strings.LastIndex(loc, "/")+1:]
}

// p35Raise sets ns's encryption to enc, a raise to e2e, and returns the
// raising entry.
func (e *tenv) p35Raise(ns string, enc map[string]any) string {
	e.t.Helper()
	expect(e.t, e.patchNS(ns, ops(op("add", "/encryption", enc)), ""), 201)
	return e.p35Head(ns)
}

// v0.73 Addendum E Levels (ENC-39), §7.1 Paging (RH-17), §E.2.2: after a
// raise from sealed to e2e, what was stored before is served as at E2,
// sealed under the last epoch before the raise: revisions, resource log
// entries, namespace documents and log ranges, a sealing stored before
// the raise unchanged. No log page spans the raise; an E3 reader folds a
// revision written end to end from the last one from before the raise.
func TestV073P35RaiseFromSealedServesSealed(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("s", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed", "pad": true}})
	r1 := e.wr("s", "d", "", withNonce(addRoot(map[string]any{"v": encMarker})))
	r2 := e.wr("s", "d", r1, withNonce(ops(op("replace", "/v", encMarker+"-2"))))
	g1 := e.get("/r/s/d/rev/" + r1)
	expect(t, g1, 200)
	keys, _ := e.keysOf("s", nil, "")
	k1 := keys["s#1"]
	pre := e.p35Head("s")
	raise := e.p35Raise("s", map[string]any{"level": "e2e", "epoch": 2.0})

	// Revisions: the stored sealing unchanged, the other sealed now under
	// epoch 1, neither with Last-Modified or Repr-Digest.
	a1 := e.get("/r/s/d/rev/" + r1)
	expect(t, a1, 200)
	if string(a1.Body) != string(g1.Body) || !isJOSE(a1) || etagOf(a1) != r1+".1" {
		t.Fatalf("revision from before the raise: %v %s", a1.H, a1.Body)
	}
	a2 := e.get("/r/s/d/rev/" + r2)
	expect(t, a2, 200)
	if !isJOSE(a2) || strings.Contains(a2.String(), encMarker) || a2.H.Get("Last-Modified") != "" || a2.H.Get("Repr-Digest") != "" {
		t.Fatalf("revision from before the raise: %v %s", a2.H, a2.Body)
	}
	if doc := jsonv.MustParse(open(t, a2.String(), resKey(t, k1, "s", "d"), "s#1", seal.ResourcePL("s", "d", r2, seal.KindDoc))).(map[string]any); doc["v"] != encMarker+"-2" {
		t.Fatalf("document %v", doc)
	}

	// A write end to end, and its fold from the last revision before.
	r3 := etagOf(expectOK(t, e.writeAs("s", "d", r2, p35Sealed(t, seal.NewKey(), "s#2", "s", "d", r2, ops(op("replace", "/v", "x"))), "alice")))
	f := e.get("/r/s/d/rev/" + r3)
	expect(t, f, 302)
	if u, _ := url.Parse(f.H.Get("Location")); f.H.Get("X-E2E") != "fold" || u.Query().Get("since") != r2 {
		t.Fatalf("fold %v", f.H)
	}
	// The log: a page from before the raise, sealed entries, ends at r2.
	l := e.get("/r/s/d/rev/" + r3 + "/log")
	expect(t, l, 200)
	if l.H.Get("X-Log-Next") != r2 || len(l.Arr()) != 2 {
		t.Fatalf("first page %v %s", l.H, l.Body)
	}
	for i, x := range l.Arr() {
		jwe, ok := x.(string)
		want := []string{r1, r2}[i]
		if !ok {
			t.Fatalf("entry %d in the clear: %v", i, x)
		}
		m := jsonv.MustParse(open(t, jwe, resKey(t, k1, "s", "d"), "s#1", seal.ResourcePL("s", "d", want, seal.KindRev))).(map[string]any)
		if m["id"] != want {
			t.Fatalf("entry %v", m)
		}
	}
	l = e.get("/r/s/d/rev/" + r3 + "/log?since=" + r2)
	expect(t, l, 200)
	if arr := l.Arr(); len(arr) != 1 || arr[0].(map[string]any)["id"] != r3 || l.H.Get("X-Log-Next") != "" {
		t.Fatalf("second page %v %s", l.H, l.Body)
	}

	// The namespace: documents and ranges from before the raise sealed
	// under epoch 1, the raising entry's in the clear; no page spans it.
	d := e.get("/ns/s/rev/" + pre)
	expect(t, d, 200)
	if !isJOSE(d) || etagOf(d) != pre+".1" {
		t.Fatalf("namespace document from before the raise %v %s", d.H, d.Body)
	}
	open(t, d.String(), k1, "s#1", seal.NamespaceDocPL("s", pre))
	d = e.get("/ns/s/rev/" + raise)
	expect(t, d, 200)
	if isJOSE(d) || d.Obj()["encryption"].(map[string]any)["level"] != "e2e" {
		t.Fatalf("raising document %s", d.Body)
	}
	nl := e.get("/ns/s/rev/" + raise + "/log")
	expect(t, nl, 200)
	if !isJOSE(nl) || nl.H.Get("X-Log-Next") != pre {
		t.Fatalf("namespace log first page %v %s", nl.H, nl.Body)
	}
	entries := jsonv.MustParse(open(t, nl.String(), k1, "s#1", seal.RangePL("s", "", pre))).([]any)
	if last := entries[len(entries)-1].(map[string]any); last["id"] != pre {
		t.Fatalf("first page ends at %v", last["id"])
	}
	nl = e.get("/ns/s/rev/" + raise + "/log?since=" + pre)
	expect(t, nl, 200)
	if isJOSE(nl) || len(nl.Arr()) != 1 || nl.Arr()[0].(map[string]any)["id"] != raise {
		t.Fatalf("namespace log second page %v %s", nl.H, nl.Body)
	}
	// A range from before the raise, in one page.
	nl = e.get("/ns/s/rev/" + pre + "/log")
	expect(t, nl, 200)
	if !isJOSE(nl) || nl.H.Get("X-Log-Next") != "" {
		t.Fatalf("range before the raise %v", nl.H)
	}

	// ENC-44: a branch of the raised namespace serves what it reads
	// through from before the raise as the base serves it: the same
	// stored bytes, kid and pl naming the base.
	expect(t, e.branch("s", map[string]any{"name": "sb"}, "admin"), 201)
	for _, id := range []string{r1, r2} {
		b, a := e.get("/r/sb/d/rev/"+id), e.get("/r/s/d/rev/"+id)
		expect(t, b, 200)
		if !isJOSE(b) || string(b.Body) != string(a.Body) {
			t.Fatalf("branch's read-through revision from before the raise: %v %s", b.H, b.Body)
		}
	}
	l = e.get("/r/sb/d/rev/" + r3 + "/log")
	if l.Code != 200 || l.H.Get("X-Log-Next") != r2 || len(l.Arr()) != 2 {
		t.Fatalf("branch's log first page %d %v %s", l.Code, l.H, l.Body)
	}
	open(t, l.Arr()[0].(string), resKey(t, k1, "s", "d"), "s#1", seal.ResourcePL("s", "d", r1, seal.KindRev))
	f = e.get("/r/sb/d/rev/" + r3)
	if u, _ := url.Parse(f.H.Get("Location")); f.Code != 302 || u.Query().Get("since") != r2 {
		t.Fatalf("branch's fold %d %v", f.Code, f.H)
	}
}

// expectOK expects a 201 and returns the answer.
func expectOK(t *testing.T, r *resp) *resp {
	t.Helper()
	expect(t, r, 201)
	return r
}

// v0.73 Addendum E Levels (ENC-39, F-E1 default), §7.1 Paging (RH-17):
// after a raise from none, revisions from before it are served in the
// clear as documents, not folded; a fold of a later one starts from the
// resource's last revision from before the raise, or from the last live
// one before a tombstone, the range then holding the tombstone in a page
// of its own.
func TestV073P35RaiseFromNoneServesClear(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("p", map[string]any{"read": "public"})
	r1 := e.wr("p", "d", "", addRoot(map[string]any{"v": 1.0}))
	r2 := e.wr("p", "d", r1, ops(op("replace", "/v", 2.0)))
	t1 := e.wr("p", "t", "", addRoot(map[string]any{"v": 1.0}))
	dr := e.do(req{method: "DELETE", path: "/r/p/t", ifMatch: t1, author: "alice"})
	expect(t, dr, 200)
	tomb := etagOf(dr)
	pre := e.p35Head("p")
	raise := e.p35Raise("p", map[string]any{"level": "e2e", "epoch": 1.0})

	g := e.get("/r/p/d/rev/" + r2)
	expect(t, g, 200)
	if isJOSE(g) || g.H.Get("X-E2E") != "" || g.H.Get("Last-Modified") != "" || g.H.Get("Repr-Digest") != "" {
		t.Fatalf("revision from before the raise %v", g.H)
	}
	mustEqual(t, g.JSON(), map[string]any{"v": 2.0})
	k := seal.NewKey()
	r3 := etagOf(expectOK(t, e.writeAs("p", "d", r2, p35Sealed(t, k, "p#1", "p", "d", r2, ops(op("replace", "/v", 3.0))), "alice")))
	f := e.get("/r/p/d/rev/" + r3)
	if u, _ := url.Parse(f.H.Get("Location")); f.Code != 302 || u.Query().Get("since") != r2 {
		t.Fatalf("fold %d %v", f.Code, f.H)
	}
	l := e.get("/r/p/d/rev/" + r3 + "/log")
	if l.Code != 200 || l.H.Get("X-Log-Next") != r2 || len(l.Arr()) != 2 {
		t.Fatalf("log first page %d %v %s", l.Code, l.H, l.Body)
	}
	// A page starting at the raise holds the first revision after it.
	l = e.get("/r/p/d/rev/" + r3 + "/log?since=" + r1)
	if l.Code != 200 || l.H.Get("X-Log-Next") != r2 || len(l.Arr()) != 1 {
		t.Fatalf("log from r1 %d %v %s", l.Code, l.H, l.Body)
	}

	// A restore written end to end over a tombstone from before.
	t2 := etagOf(expectOK(t, e.writeAs("p", "t", tomb, p35Sealed(t, k, "p#1", "p", "t", tomb, ops(op("replace", "/v", 2.0))), "alice")))
	f = e.get("/r/p/t/rev/" + t2)
	if u, _ := url.Parse(f.H.Get("Location")); f.Code != 302 || u.Query().Get("since") != t1 {
		t.Fatalf("fold over a tombstone %d %v", f.Code, f.H)
	}
	l = e.get("/r/p/t/rev/" + t2 + "/log?since=" + t1)
	if arr := l.Arr(); l.Code != 200 || l.H.Get("X-Log-Next") != tomb || len(arr) != 1 || arr[0].(map[string]any)["kind"] != "tombstone" {
		t.Fatalf("tombstone page %d %v %s", l.Code, l.H, l.Body)
	}
	l = e.get("/r/p/t/rev/" + t2 + "/log?since=" + tomb)
	if arr := l.Arr(); l.Code != 200 || len(arr) != 1 || arr[0].(map[string]any)["id"] != t2 {
		t.Fatalf("restore page %d %s", l.Code, l.Body)
	}

	// The namespace log: a page ends before the raising entry.
	nl := e.get("/ns/p/rev/" + raise + "/log")
	arr := nl.Arr()
	if nl.Code != 200 || nl.H.Get("X-Log-Next") != pre || arr[len(arr)-1].(map[string]any)["id"] != pre {
		t.Fatalf("namespace log %d %v", nl.Code, nl.H)
	}
}

// v0.73 Addendum E Levels (ENC-41), §7.1, §E.2.2 Epochs (RH-48): blobs
// referenced by revisions from before a raise from sealed keep their epoch
// URLs, under those revisions' epochs only, and …/blob/{bid} redirects to
// them, a blob none of whose revisions has an epoch yet fixing the newest
// under the epoch it is served under; they are never served in the clear.
// Other blobs at E3 are served as uploaded, their epoch URLs 404
// not_offered, and so after a raise from none.
func TestV073P35PreRaiseBlobs(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t, withoutBlobSweep)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	data := []byte("pre-raise blob " + encMarker)
	n1 := seal.NewNonce()
	_, b1 := e.putBlob("s", "d", "text/plain", n1, data)
	r1 := e.wr("s", "d", "", withNonce(addRoot(map[string]any{"b": ref(b1, "text/plain", len(data), n1)})))
	expect(t, e.get(blobPath("s", "d", b1)), 302) // fixes epoch 1 at E2
	data2 := []byte("second blob " + encMarker)
	n2 := seal.NewNonce()
	_, b2 := e.putBlob("s", "d", "text/plain", n2, data2)
	r2 := e.wr("s", "d", r1, withNonce(ops(op("add", "/c", ref(b2, "text/plain", len(data2), n2)))))
	keys, _ := e.keysOf("s", nil, "")
	e.p35Raise("s", map[string]any{"level": "e2e", "epoch": 2.0})

	for _, b := range []struct{ bid, data string }{{b1, string(data)}, {b2, string(data2)}} {
		g := e.get(blobPath("s", "d", b.bid))
		if g.Code != 302 || g.H.Get("Location") != blobPath("s", "d", b.bid)+"/e/1" || strings.Contains(g.String(), encMarker) {
			t.Fatalf("blob from before the raise: %d %v %s", g.Code, g.H, g.Body)
		}
		s := e.get(blobPath("s", "d", b.bid) + "/e/1")
		expect(t, s, 200)
		if s.H.Get("Content-Type") != core.SealedBlobType || etagOf(s) != b.bid+".1" {
			t.Fatalf("sealed blob %v", s.H)
		}
		if got := openSealedBlob(t, s.Body, resKey(t, keys["s#1"], "s", "d"), "s#1", seal.BlobPL("s", "d", b.bid)); string(got) != b.data {
			t.Fatalf("opened %q", got)
		}
		g = e.get(blobPath("s", "d", b.bid) + "/e/2")
		if g.Code != 404 || g.H.Get("Cache-Control") != "no-store" {
			t.Fatalf("epoch after the raise: %d %v", g.Code, g.H)
		}
	}
	// A blob written end to end: as uploaded, without epoch URLs.
	ref3 := e.uploadE2E("s", "d", []byte("e2e blob"), "alice")
	b3 := ref3["$blob"].(string)
	expectOK(t, e.writeAs("s", "d", r2, p35Sealed(t, seal.NewKey(), "s#2", "s", "d", r2, ops(op("add", "/e", ref3)), b3), "alice"))
	g := e.get(blobPath("s", "d", b3))
	if g.Code != 200 || g.H.Get("Content-Type") != core.SealedBlobType {
		t.Fatalf("blob written end to end %d %v", g.Code, g.H)
	}
	expectCode(t, e.get(blobPath("s", "d", b3)+"/e/1"), 404, "not_offered")

	// After a raise from none, blobs are as at the level before.
	e.mkNS("p", map[string]any{"read": "public"})
	_, pb := e.putBlob("p", "d", "text/plain", "", data)
	e.wr("p", "d", "", addRoot(map[string]any{"b": ref(pb, "text/plain", len(data), "")}))
	e.p35Raise("p", map[string]any{"level": "e2e", "epoch": 1.0})
	g = e.get(blobPath("p", "d", pb))
	if g.Code != 200 || g.String() != string(data) {
		t.Fatalf("blob from before a raise from none %d %v", g.Code, g.H)
	}
	expectCode(t, e.get(blobPath("p", "d", pb)+"/e/1"), 404, "not_offered")
}

// v0.73 §C.3.1, Addendum E Levels (ENC-40, GR-33): in a namespace raised
// from sealed, a grant first recorded before the raise stays sealed as at
// E2 (pl {ns, grant}, the epoch of the entry recording it); one recorded
// after it is served in the clear. Both are private, no-store at the
// edge (§9).
func TestV073P35PreRaiseGrants(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	admin, writer := newKey("admin"), newKey("writer")
	e.mkNS("s", sealedDoc(map[string]any{"keys": []any{admin.entry("*"), writer.entry("read", "create", "append")}}))
	adminG := e.grant(admin, "user:admin", []string{"s"}, allVerbs)
	g1 := e.grant(writer, "user:w1", []string{"s"}, []string{"read", "create", "append"})
	g2 := e.grant(writer, "user:w2", []string{"s"}, []string{"read", "create", "append"})
	r1 := e.wr("s", "d", "", withNonce(addRoot(map[string]any{"v": 1.0})), g1)
	keys, _ := e.keysOf("s", nil, adminG)
	expect(t, e.patchNS("s", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), adminG), 201)
	r := e.do(req{method: "PATCH", path: "/r/s/d", ifMatch: r1, raw: p35Sealed(t, seal.NewKey(), "s#2", "s", "d", r1, ops(op("replace", "/v", 2.0))), hasRaw: true, bearer: g2})
	expect(t, r, 201)

	gid1, gid2 := grantIDOf(t, g1), grantIDOf(t, g2)
	a := e.get("/ns/s/grants/"+gid1, adminG)
	expect(t, a, 200)
	if !isJOSE(a) || !strings.HasPrefix(a.H.Get("Cache-Control"), "private") || a.H.Get("CDN-Cache-Control") != "no-store" {
		t.Fatalf("grant from before the raise %v %s", a.H, a.Body)
	}
	m := jsonv.MustParse(open(t, a.String(), keys["s#1"], "s#1", seal.GrantPL("s", gid1))).(map[string]any)
	if m["id"] != gid1 {
		t.Fatalf("grant %v", m)
	}
	b := e.get("/ns/s/grants/"+gid2, adminG)
	expect(t, b, 200)
	if isJOSE(b) || b.Obj()["id"] != gid2 || !strings.HasPrefix(b.H.Get("Cache-Control"), "private") || b.H.Get("CDN-Cache-Control") != "no-store" {
		t.Fatalf("grant after the raise %v %s", b.H, b.Body)
	}
	// A branch serves its base's grant from before the raise as the base
	// does (ENC-44).
	expect(t, e.branch("s", map[string]any{"name": "sb"}, adminG), 201)
	adminB := e.grant(admin, "user:admin", []string{"sb"}, allVerbs)
	c := e.get("/ns/sb/grants/"+gid1, adminB)
	expect(t, c, 200)
	if string(c.Body) != string(a.Body) {
		t.Fatalf("branch's grant from before the base's raise %v %s", c.H, c.Body)
	}
}

// v0.73 §6.1 Read permission (CIS-24), §2.1 Protection, §7.8 (BBD-29,
// BBD-30), Addendum E Levels: in a namespace raised from sealed, content
// from before the raise is moved or resolved only with keys that open it
// under the epoch it is served under, as /keys gives them as at E2 to the
// request's grant: the §E.2.3 window applied to the epochs before the
// raise, the last one standing for the current. A grant without nbf gets
// only epoch 2, the last before the raise; one with nbf at the start gets
// 1 and 2. A schema revision written at epoch 1 then resolves only for the
// latter, and its blob is copied, or made available through a batch's
// local source, only for it; one written at e2e never resolves.
func TestV073P35PreRaiseKeyWindows(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t, withoutBlobSweep)
	admin := newKey("admin")
	keys := []any{admin.entry("*")}
	e.mkNS("sch", sealedDoc(map[string]any{"keys": keys}))
	e.mkNS("docs", map[string]any{"keys": keys})
	e.mkNS("e3", e2eDoc(map[string]any{"keys": keys}))
	nss := []string{"sch", "docs", "e3"}
	early := e.grant(admin, "user:early", nss, allVerbs, map[string]any{"nbf": e.clock.Now().Format(time.RFC3339)})
	s1 := e.wr("sch", "m", "", withNonce(addRoot(matchSchema())), early)
	blob := []byte("sealed-type blob " + encMarker)
	_, bid := e.putBlob("sch", "d", core.SealedBlobType, "", blob, early)
	plain := []byte("plain blob " + encMarker)
	_, pid := e.putBlob("sch", "d", "text/plain", "", plain, early)
	e.wr("sch", "d", "", withNonce(addRoot(map[string]any{"b": ref(bid, core.SealedBlobType, len(blob), ""), "p": ref(pid, "text/plain", len(plain), "")})), early)
	e.clock.Advance(time.Minute)
	expect(t, e.patchNS("sch", ops(op("add", "/encryption/epoch", 2.0)), early), 201)
	e.clock.Advance(time.Minute)
	expect(t, e.patchNS("sch", ops(op("add", "/encryption", map[string]any{"level": "e2e", "epoch": 3.0})), early), 201)
	late := e.grant(admin, "user:late", nss, allVerbs)

	// CIS-24: a schema revision from before the raise from sealed.
	doc := addRoot(map[string]any{"$schema": "/r/sch/m/rev/" + s1, "score": "1-0"})
	expectCode(t, e.write("PATCH", "docs", "x", "", doc, late), 422, "schema_unavailable")
	expect(t, e.write("PATCH", "docs", "x", "", doc, early), 201)
	expectCode(t, e.write("PATCH", "docs", "y", "", addRoot(map[string]any{"$schema": "/r/sch/m/rev/" + s1, "score": 1.0}), early), 422, "invalid")
	// One written at e2e doesn't resolve.
	s2 := etagOf(expectOK(t, e.do(req{method: "PATCH", path: "/r/sch/m", ifMatch: s1, raw: p35Sealed(t, seal.NewKey(), "sch#3", "sch", "m", s1, ops(op("add", "/title", "t"))), hasRaw: true, bearer: early})))
	expectCode(t, e.write("PATCH", "docs", "z", "", addRoot(map[string]any{"$schema": "/r/sch/m/rev/" + s2, "score": "1-0"}), early), 422, "schema_unavailable")

	// BBD-29: a copy of a blob from before the raise.
	from := blobPath("sch", "d", bid)
	expectCode(t, e.copyBlob("e3", "x", bid, from, "", late), 404, "not_found")
	expect(t, e.copyBlob("e3", "x", bid, from, "", early), 201)

	// BBD-30: a batch's local source makes it available only so.
	at := e.nsHead("sch", early)
	body := map[string]any{"source": map[string]any{"ns": "sch", "at": at},
		"items": []any{map[string]any{"resource": "d", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"p": ref(pid, "text/plain", len(plain), "")})}}}}
	expectCode(t, e.batchReq("docs", body, late), 422, "batch")
	expect(t, e.batchReq("docs", body, early), 201)
}

// v0.73 §9 ("/ns/{ns}/grants/{gid} (private at E3, §C.3.1)"), §C.3.1: a
// grant from before a raise from sealed, served sealed, is still an E3
// grant answer, private and no-store at the edge, in a public namespace
// too, whose sealed answers otherwise take the immutable class.
func TestV073P35PreRaiseGrantPrivatePublic(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	admin, writer := newKey("admin"), newKey("writer")
	e.mkNS("s", sealedDoc(map[string]any{"read": "public", "keys": []any{admin.entry("*"), writer.entry("read", "create", "append")}}))
	adminG := e.grant(admin, "user:admin", []string{"s"}, allVerbs)
	g1 := e.grant(writer, "user:w1", []string{"s"}, []string{"read", "create", "append"})
	e.wr("s", "d", "", withNonce(addRoot(map[string]any{"v": 1.0})), g1)
	expect(t, e.patchNS("s", ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0})), adminG), 201)

	a := e.get("/ns/s/grants/"+grantIDOf(t, g1), adminG)
	expect(t, a, 200)
	if !isJOSE(a) {
		t.Fatalf("grant from before the raise not sealed: %v", a.H)
	}
	if cc := a.H.Get("Cache-Control"); !strings.HasPrefix(cc, "private") || a.H.Get("CDN-Cache-Control") != "no-store" || a.H.Get("Surrogate-Control") != "no-store" {
		t.Fatalf("E3 grant answer from before the raise cached as %q (CDN %q), not private/no-store", cc, a.H.Get("CDN-Cache-Control"))
	}
}

// v0.73 §6.1, Addendum E Levels (CIS-24): a schema revision from before a
// raise from none is served at E3 in the clear, as at the level before,
// with the rules marker its row was stored with, as the server compiles
// it when it resolves it: an E3 client without the marker compiles it as
// legacy (idn-email unasserted where the server asserts it).
func TestV073P35PreRaiseSchemaRulesMarker(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("p", map[string]any{"read": "public"})
	s1 := e.wr("p", "m", "", addRoot(map[string]any{"$schema": dialect, "properties": map[string]any{"m": map[string]any{"format": "idn-email"}}}))
	before := e.get("/r/p/m/rev/" + s1)
	expect(t, before, 200)
	if before.H.Get(schema.RulesHeader) != "v0.73" {
		t.Fatalf("marker before the raise %q", before.H.Get(schema.RulesHeader))
	}
	e.p35Raise("p", map[string]any{"level": "e2e", "epoch": 1.0})
	after := e.get("/r/p/m/rev/" + s1)
	expect(t, after, 200)
	if isJOSE(after) || after.H.Get("X-E2E") != "" {
		t.Fatalf("revision from before the raise %v", after.H)
	}
	if got := after.H.Get(schema.RulesHeader); got != "v0.73" {
		t.Fatalf("schema revision from before a raise from none served at E3 with marker %q, want v0.73", got)
	}
	// Created and digest follow the level now in force (§E.3.1).
	if after.H.Get("Last-Modified") != "" || after.H.Get("Repr-Digest") != "" {
		t.Fatalf("revision from before the raise at E3 %v", after.H)
	}
}
