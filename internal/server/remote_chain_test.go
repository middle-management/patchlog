package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
)

// §G.3 remote branches whose base is itself a branch on A: B verifies the
// read-through heads against the logs of the bases that wrote them, and
// mirrors each level of A's chain into a shadow of its own.

type chainFixture struct {
	at1, atA   string // matches' head when r7 was made; r7's head B branches at
	s1         string // schema
	d1, d2     string // derby, in matches: read through by r7
	o1         string // own, in matches
	o2, o3     string // own, in r7: o2's parent is foreign (o1)
	g1, gt     string // gone: tombstoned in matches before at1
	c1         string // c: purged in matches before at1
	n1         string // fresh: created in r7
	lateD      string // derby in matches after at1
	lateO      string // own in r7 after atA
	e1         string // e, in matches (a batch)
	genesisR7  string // the first entry of r7's log
	lateInBase string
}

func populateChain(t *testing.T, a *tenv) chainFixture {
	t.Helper()
	var f chainFixture
	a.mkNS("schemas", map[string]any{"read": "public"})
	f.s1 = a.create("schemas", "match", matchSchema())
	a.mkNS("matches", map[string]any{"read": "public", "x-title": "A's matches"})
	f.d1 = a.create("matches", "derby", map[string]any{"$schema": "/r/schemas/match/rev/" + f.s1, "score": "0-0"})
	f.d2 = a.appendRev("matches", "derby", f.d1, ops(op("replace", "/score", "1-0")))
	f.o1 = a.create("matches", "own", map[string]any{"v": 1.0})
	f.g1 = a.create("matches", "gone", map[string]any{"g": true})
	f.gt = a.del("matches", "gone", f.g1)
	f.c1 = a.create("matches", "c", map[string]any{"secret": true})
	expect(t, a.purge("matches", "c", f.c1, "admin"), 204)
	r := a.do(req{method: "POST", path: "/ns/matches/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "e", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"e": 1.0})}},
		map[string]any{"resource": "f", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"f": 1.0}), ops(op("add", "/g", 2.0))}},
	}}})
	expect(t, r, 201)
	f.at1 = a.nsHead("matches")
	f.e1 = headAt(t, a, "matches", f.at1, "e")
	f.lateD = a.appendRev("matches", "derby", f.d2, ops(op("replace", "/score", "5-0")))
	f.lateInBase = a.create("matches", "late", map[string]any{})

	expect(t, a.branch("matches", map[string]any{"name": "r7", "at": f.at1}, "alice"), 201)
	f.o2 = a.appendRev("r7", "own", f.o1, ops(op("replace", "/v", 2.0)))
	f.o3 = a.appendRev("r7", "own", f.o2, ops(op("add", "/w", true)))
	f.n1 = a.create("r7", "fresh", map[string]any{"fresh": true})
	f.atA = a.nsHead("r7")
	f.lateO = a.appendRev("r7", "own", f.o3, ops(op("replace", "/v", 9.0)))
	f.genesisR7 = a.nsLog("r7")[0]["id"].(string)
	return f
}

// sameRead checks that B's name in ns serves what A's name in ans serves at
// id: the document and the log, byte for byte.
func sameRead(t *testing.T, a, b *tenv, ans, bns, name, id string, query string) {
	t.Helper()
	da, db := a.get("/r/"+ans+"/"+name+"/rev/"+id), b.get("/r/"+bns+"/"+name+"/rev/"+id)
	if da.Code != 200 || db.Code != 200 || string(canonical(da.JSON())) != string(canonical(db.JSON())) {
		t.Fatalf("%s@%s: documents differ: A %d %s, B %d %s", name, id, da.Code, da.Body, db.Code, db.Body)
	}
	la := a.get("/r/" + ans + "/" + name + "/rev/" + id + "/log" + query)
	lb := b.get("/r/" + bns + "/" + name + "/rev/" + id + "/log" + query)
	if la.Code != 200 || !bytes.Equal(la.Body, lb.Body) {
		t.Fatalf("%s@%s%s: logs differ\nA %d %s\nB %d %s", name, id, query, la.Code, la.Body, lb.Code, lb.Body)
	}
}

func sameHeads(t *testing.T, a, b *tenv, ans, at, bns string) {
	t.Helper()
	ha := a.get("/ns/" + ans + "/rev/" + at + "/heads").Obj()["items"]
	hb := b.get("/ns/" + bns + "/rev/" + b.nsHead(bns) + "/heads").Obj()["items"]
	if string(canonical(hb)) != string(canonical(ha)) {
		t.Fatalf("heads differ\nA %s\nB %s", canonical(ha), canonical(hb))
	}
}

// A remote branch of A's branch r7 reads what r7 serves at atA: its own
// resources, those it reads through from matches as of at1, logs crossing
// foreign parents, tombstones and purges; B's first writes take the right
// parents.
func TestRemoteBranchOfBranch(t *testing.T) {
	a, b, _ := pair(t, nil, nil)
	f := populateChain(t, a)

	expect(t, b.mkRemote("rel", remoteGenesis("r7", f.atA, nil)), 201)
	if k := b.nsKinds("rel"); len(k) != 1 || k[0] != "config" {
		t.Fatalf("remote branch log %v", k)
	}
	// Neither shadow can be addressed.
	expect(t, b.get("/ns/~rel"), 400)
	expect(t, b.get("/ns/~rel~1"), 400)
	expect(t, b.get("/r/~rel~1/derby"), 400)

	want := map[string]string{"derby": f.d2, "own": f.o3, "e": f.e1, "fresh": f.n1}
	for name, id := range want {
		if got := headAt(t, a, "r7", f.atA, name); got != id {
			t.Fatalf("fixture: A's r7 %s at %s, want %s", name, got, id)
		}
		if got := b.head("rel", name); got != id {
			t.Fatalf("%s: head %s, want %s", name, got, id)
		}
		sameRead(t, a, b, "r7", "rel", name, id, "")
	}
	sameRead(t, a, b, "r7", "rel", "f", headAt(t, a, "r7", f.atA, "f"), "")
	// History across the foreign parent, and ids below it.
	lg := b.get("/r/rel/own/rev/" + f.o3 + "/log").Arr()
	if len(lg) != 3 || lg[0].(map[string]any)["id"] != f.o1 || lg[1].(map[string]any)["parent"] != f.o1 {
		t.Fatalf("own's log across the foreign parent %v", lg)
	}
	sameRead(t, a, b, "r7", "rel", "own", f.o3, "?since="+f.o1)
	sameRead(t, a, b, "r7", "rel", "own", f.o1, "")
	sameRead(t, a, b, "r7", "rel", "derby", f.d1, "")
	// Tombstoned and purged in matches before at1; later changes invisible.
	g := b.get("/r/rel/gone")
	expectCode(t, g, 410, "gone")
	if g.Str("tombstone") != f.gt || g.Str("last") != f.g1 {
		t.Fatalf("tombstoned read-through %s", g.Body)
	}
	expect(t, b.get("/r/rel/c"), 410)
	expect(t, b.get("/r/rel/c/rev/"+f.c1), 410)
	expect(t, b.get("/r/rel/late"), 404)
	expect(t, b.get("/r/rel/derby/rev/"+f.lateD), 404)
	expect(t, b.get("/r/rel/own/rev/"+f.lateO), 404)
	sameHeads(t, a, b, "r7", f.atA, "rel")
	// The schema of a read-through document is mirrored.
	if b.head("schemas", "match") != f.s1 {
		t.Fatal("mirrored schema")
	}

	// First writes: onto a read-through resource, the foreign parent is
	// matches' head as of at1; onto r7's own, r7's head as of atA.
	r := b.write("PATCH", "rel", "derby", f.lateD, ops(op("replace", "/score", "9-9")))
	expectCode(t, r, 412, "stale")
	if r.Str("head") != f.d2 {
		t.Fatalf("412 %s", r.Body)
	}
	expectCode(t, b.write("PATCH", "rel", "derby", f.d2, ops(op("replace", "/score", 3.0))), 422, "invalid")
	p := ops(op("replace", "/score", "2-0"))
	w := b.appendRev("rel", "derby", f.d2, p)
	if w != hashID(t, f.d2, canonical(p)) {
		t.Fatal("the foreign parent was not used")
	}
	lg = b.get("/r/rel/derby/rev/" + w + "/log").Arr()
	if len(lg) != 3 || lg[0].(map[string]any)["id"] != f.d1 || lg[2].(map[string]any)["parent"] != f.d2 {
		t.Fatalf("derby's log across the foreign parent %v", lg)
	}
	expectCode(t, b.write("PATCH", "rel", "own", f.o1, ops(op("replace", "/v", 3.0))), 412, "stale")
	p = ops(op("replace", "/v", 3.0))
	wo := b.appendRev("rel", "own", f.o3, p)
	if wo != hashID(t, f.o3, canonical(p)) {
		t.Fatal("own's parent")
	}
	if lg = b.get("/r/rel/own/rev/" + wo + "/log").Arr(); len(lg) != 4 || lg[0].(map[string]any)["id"] != f.o1 {
		t.Fatalf("own's log %v", lg)
	}
	if rs := b.appendRev("rel", "gone", f.gt, []any{}); rs != hashID(t, f.gt, canonical([]any{})) {
		t.Fatal("restore of a mirrored tombstone")
	}
	b.create("rel", "late", map[string]any{"mine": true})
	if b.doc("rel", "own")["v"] != 3.0 || b.doc("rel", "fresh")["fresh"] != true {
		t.Fatal("documents after writes")
	}
	if a.head("r7", "own") != f.lateO || a.head("matches", "derby") != f.lateD {
		t.Fatal("A changed")
	}
	// Local branches of the remote branch work as usual, and count every
	// level of the chain.
	expect(t, b.branch("rel", map[string]any{"name": "rel-b"}, "alice"), 201)
	if b.head("rel-b", "derby") != w || b.head("rel-b", "e") != f.e1 || b.head("rel-b", "own") != wo {
		t.Fatal("branch of a remote branch")
	}
	b.e.FlushCaches()
	if b.doc("rel", "e")["e"] != 1.0 || b.doc("rel", "f")["g"] != 2.0 || b.doc("rel-b", "own")["w"] != true {
		t.Fatal("after flush")
	}
}

// A branch of a branch on A: three levels, with a resource whose chain
// crosses both foreign parents.
func TestRemoteBranchTwoLevels(t *testing.T) {
	a, b, _ := pair(t, nil, nil)
	f := populateChain(t, a)
	x1 := a.create("matches", "x", map[string]any{"n": 1.0})
	_ = x1
	// x was created after at1: r7 doesn't see it. Build x's chain in r7.
	x2 := a.create("r7", "x", map[string]any{"n": 2.0})
	atR7 := a.nsHead("r7")
	expect(t, a.branch("r7", map[string]any{"name": "r7b", "at": atR7}, "alice"), 201)
	o4 := a.appendRev("r7b", "own", f.lateO, ops(op("replace", "/v", 4.0)))
	x3 := a.appendRev("r7b", "x", x2, ops(op("replace", "/n", 3.0)))
	mine := a.create("r7b", "mine", map[string]any{"m": true})
	atB := a.nsHead("r7b")
	a.appendRev("r7b", "own", o4, ops(op("replace", "/v", 5.0))) // after atB

	expect(t, b.mkRemote("rel", remoteGenesis("r7b", atB, nil)), 201)
	want := map[string]string{"own": o4, "x": x3, "mine": mine, "fresh": f.n1, "derby": f.d2, "e": f.e1}
	for name, id := range want {
		if got := b.head("rel", name); got != id {
			t.Fatalf("%s: head %s, want %s", name, got, id)
		}
		sameRead(t, a, b, "r7b", "rel", name, id, "")
	}
	lg := b.get("/r/rel/own/rev/" + o4 + "/log").Arr()
	if len(lg) != 5 || lg[0].(map[string]any)["id"] != f.o1 || lg[3].(map[string]any)["id"] != f.lateO || lg[4].(map[string]any)["parent"] != f.lateO {
		t.Fatalf("own's log across two foreign parents %v", lg)
	}
	sameRead(t, a, b, "r7b", "rel", "own", o4, "?since="+f.o2)
	sameRead(t, a, b, "r7b", "rel", "own", f.o1, "")
	sameHeads(t, a, b, "r7b", atB, "rel")
	expect(t, b.get("/r/rel/gone"), 410)
	expect(t, b.get("/r/rel/c"), 410)

	// Writes: onto something r7b reads through from r7 (whose own chain has
	// a foreign parent into matches), and from matches.
	p := ops(op("add", "/b", true))
	if w := b.appendRev("rel", "fresh", f.n1, p); w != hashID(t, f.n1, canonical(p)) {
		t.Fatal("fresh's foreign parent")
	}
	if w := b.appendRev("rel", "e", f.e1, p); w != hashID(t, f.e1, canonical(p)) {
		t.Fatal("e's foreign parent")
	}
	if lg := b.get("/r/rel/e/rev/" + hashID(t, f.e1, canonical(p)) + "/log").Arr(); len(lg) != 2 {
		t.Fatalf("e's log %v", lg)
	}
	expect(t, b.branch("rel", map[string]any{"name": "rel-b"}, "alice"), 201)
	if b.head("rel-b", "derby") != f.d2 || b.doc("rel-b", "own")["v"] != 4.0 {
		t.Fatal("branch of a three-level remote branch")
	}
}

// Tampering with any level's data is 502, and nothing is written.
func TestRemoteBranchOfBranchTampered(t *testing.T) {
	a, b, rt := pair(t, nil, nil)
	f := populateChain(t, a)
	cases := []struct {
		name, match, from, to string
	}{
		{"base's namespace log", "/ns/matches/rev/" + f.at1 + "/log", `"resource":"own"`, `"resource":"owm"`},
		{"base's resource log", "/r/matches/derby/rev/", `"1-0"`, `"7-0"`},
		{"base's entries in a crossing log", "/r/r7/own/rev/", `"v":1`, `"v":7`},
		{"branch's genesis (its at)", "/ns/r7/rev/", f.at1, hashID(t, "", nil)},
		{"heads", "/heads", `"resource":"e"`, `"resource":"x"`},
	}
	for _, c := range cases {
		rt.set(tamper(t, a, c.match, func(b []byte) []byte { return bytes.ReplaceAll(b, []byte(c.from), []byte(c.to)) }), "")
		r := b.mkRemote("rel", remoteGenesis("r7", f.atA, nil))
		if r.Code != 502 || r.Str("code") != "remote" {
			t.Errorf("%s: %d %s", c.name, r.Code, r.Body)
		}
		expect(t, b.get("/ns/rel"), 404)
		expect(t, b.get("/ns/schemas"), 404)
	}
	rt.set(tamper(t, a, "/nothing", nil), "")
	expect(t, b.mkRemote("rel", remoteGenesis("r7", f.atA, nil)), 201)
}

// refusing serves A through a proxy that answers status for paths
// containing match.
func refusing(t *testing.T, a *tenv, match string, status int) string {
	t.Helper()
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, match) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			w.Write([]byte(`{"code":"forbidden"}`))
			return
		}
		hr, _ := http.NewRequest(r.Method, a.srv.URL+r.URL.RequestURI(), r.Body)
		hr.Header = r.Header.Clone()
		res, err := client.Do(hr)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		for k, v := range res.Header {
			if k != "Content-Length" {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(res.StatusCode)
		w.Write(body)
	}))
	t.Cleanup(p.Close)
	return p.URL
}

// If B can't read a base of A's branch, it can't create the remote branch.
func TestRemoteBranchOfBranchUnreadableBase(t *testing.T) {
	a, b, rt := pair(t, nil, nil)
	f := populateChain(t, a)
	for _, status := range []int{401, 403, 404} {
		rt.set(refusing(t, a, "/matches/", status), "")
		r := b.mkRemote("rel", remoteGenesis("r7", f.atA, nil))
		expectCode(t, r, 422, "invalid")
		if !strings.Contains(r.Str("message"), "matches") {
			t.Fatalf("%d: message %s", status, r.Body)
		}
		expect(t, b.get("/ns/rel"), 404)
	}
	// A base of a plain namespace isn't needed.
	expect(t, b.mkRemote("plain", remoteGenesis("schemas", a.nsHead("schemas"), nil)), 201)
}

// With authentication at A: a grant for r7 alone reads r7 (and what it
// reads through, as r7), but not matches.
func TestRemoteBranchOfBranchGrantScope(t *testing.T) {
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv))
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("matches", map[string]any{"read": "grant", "keys": []any{kA.entry("*")}})
	root := a.grant(kA, "user:root", []string{"matches", "r7"}, []string{"read", "create", "append", "branch"})
	d := a.create("matches", "d", map[string]any{"v": 1.0}, root)
	at1 := a.nsHead("matches", root)
	expect(t, a.do(req{method: "POST", path: "/ns/matches/branches", ifNoneMatch: "*", bearer: root,
		body: map[string]any{"name": "r7", "at": at1}}), 201)
	atA := a.nsHead("r7", root)

	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"r7"}, []string{"read"})}
	b := newEnv(t, withOrigin(originB), withRemote(rt))
	genesis := remoteGenesis("r7", atA, map[string]any{"read": "grant"})
	r := b.mkRemote("rel", genesis)
	expectCode(t, r, 422, "invalid")
	expect(t, b.get("/ns/rel"), 404)
	rt.set(a.srv.URL, a.grant(kA, "svc:b", []string{"r7", "matches"}, []string{"read"}))
	expect(t, b.mkRemote("rel", genesis), 201)
	if b.head("rel", "d") != d {
		t.Fatal("read-through")
	}
}

// The branch-depth limit counts every namespace of A's chain.
func TestRemoteBranchDepth(t *testing.T) {
	lim := func(n int) envOpt {
		return func(o *core.Options) {
			m := core.DefaultLimits()
			m.BranchDepth = n
			o.Maximums = m
		}
	}
	a, b, rt := pair(t, nil, []envOpt{lim(1)})
	f := populateChain(t, a)
	expectCode(t, b.mkRemote("rel", remoteGenesis("r7", f.atA, nil)), 422, "limit")
	expect(t, b.get("/ns/rel"), 404)
	expect(t, b.mkRemote("rel", remoteGenesis("matches", f.at1, nil)), 201)

	b2 := newEnv(t, withOrigin(originB), withRemote(rt), lim(2))
	expect(t, b2.mkRemote("rel", remoteGenesis("r7", f.atA, nil)), 201)
	expectCode(t, b2.branch("rel", map[string]any{"name": "rel-b"}, "alice"), 422, "limit")
}

// A's purge in matches propagates to r7 at A, as purge entries in r7's log,
// which B follows (§8.3, §G.3).
func TestRemoteBranchOfBranchPurge(t *testing.T) {
	a, b, _ := pair(t, nil, nil)
	f := populateChain(t, a)
	expect(t, b.mkRemote("rel", remoteGenesis("r7", f.atA, nil)), 201)
	expect(t, b.branch("rel", map[string]any{"name": "rel-b"}, "alice"), 201)
	ctx := context.Background()
	if err := b.e.SyncRemotes(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := b.e.RemoteNotices(ctx, "rel"); len(n) != 0 {
		t.Fatalf("notices before any purge %v", n)
	}
	// e is read through by r7; own has r7's entries on matches' o1.
	expect(t, a.purge("matches", "e", f.e1, "admin"), 204)
	expect(t, a.purge("matches", "own", f.o1, "admin"), 204)
	if k := a.nsKinds("r7"); lastOf(k) != "purge" || k[len(k)-2] != "purge" {
		t.Fatalf("fixture: r7's log %v", k)
	}
	if err := b.e.SyncRemotes(ctx); err != nil {
		t.Fatal(err)
	}
	ns, err := b.e.RemoteNotices(ctx, "rel")
	if err != nil || len(ns) != 2 || !ns[0].Applied || ns[0].Resource != "e" || ns[1].Resource != "own" || ns[1].Kind != "purge" {
		t.Fatalf("notices %+v %v", ns, err)
	}
	for _, p := range []string{"/r/rel/e", "/r/rel/e/rev/" + f.e1, "/r/rel-b/e",
		"/r/rel/own", "/r/rel/own/rev/" + f.o3, "/r/rel/own/rev/" + f.o1, "/r/rel-b/own"} {
		if g := b.get(p); g.Code != 410 {
			t.Errorf("%s after A's purge: %d %s", p, g.Code, g.Body)
		}
	}
	if k := b.nsKinds("rel"); lastOf(k) != "purge" || k[len(k)-2] != "purge" {
		t.Fatalf("remote branch log %v", k)
	}
	if b.head("rel", "derby") != f.d2 || b.head("rel", "fresh") != f.n1 {
		t.Fatal("unpurged resources")
	}
	// A remote branch made after the purge sees it too.
	atA2 := a.nsHead("r7")
	expect(t, b.mkRemote("rel2", remoteGenesis("r7", atA2, nil)), 201)
	expect(t, b.get("/r/rel2/e"), 410)
	expect(t, b.get("/r/rel2/own"), 410)
	sameHeads(t, a, b, "r7", atA2, "rel2")
	// And one at the old at, whose /heads now lists the purges.
	expect(t, b.mkRemote("rel3", remoteGenesis("r7", f.atA, nil)), 201)
	expect(t, b.get("/r/rel3/e"), 410)
	expect(t, b.get("/r/rel3/own/rev/"+f.o1), 410)
}
