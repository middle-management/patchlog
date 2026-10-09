package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

// §G.3 remote branches: two in-process deployments, A (the base) and B (the
// remote branch), with different origins.

const (
	originA = "https://a.example"
	originB = "https://b.example"
)

// route is where B reaches A: A's server, or a proxy in front of it, with
// the grant B sends.
type route struct {
	mu     sync.Mutex
	url    string
	bearer string
}

func (r *route) set(url, bearer string) {
	r.mu.Lock()
	r.url, r.bearer = url, bearer
	r.mu.Unlock()
}

func withOrigin(o string) envOpt { return func(opt *core.Options) { opt.Origin = o } }

// withRemote makes a deployment reach originA through rt; the follower runs
// only when a test calls SyncRemotes.
func withRemote(rt *route, mod ...func(*core.RemoteOptions)) envOpt {
	return func(o *core.Options) {
		o.Remote = core.RemoteOptions{FollowInterval: -1, Resolve: func(origin string) (core.RemoteEndpoint, error) {
			if origin != originA {
				return core.RemoteEndpoint{}, fmt.Errorf("unknown origin %s", origin)
			}
			rt.mu.Lock()
			defer rt.mu.Unlock()
			return core.RemoteEndpoint{BaseURL: rt.url, Bearer: rt.bearer, HTTPClient: httpClient}, nil
		}}
		for _, m := range mod {
			m(&o.Remote)
		}
	}
}

// pair starts A and B; B reaches A directly.
func pair(t *testing.T, aOpts, bOpts []envOpt, bMod ...func(*core.RemoteOptions)) (a, b *tenv, rt *route) {
	t.Helper()
	a = newEnv(t, append([]envOpt{withOrigin(originA)}, aOpts...)...)
	rt = &route{url: a.srv.URL}
	b = newEnv(t, append([]envOpt{withOrigin(originB), withRemote(rt, bMod...)}, bOpts...)...)
	return a, b, rt
}

func remoteGenesis(ns, at string, extra map[string]any) []any {
	doc := map[string]any{"read": "public", "base": map[string]any{"origin": originA, "ns": ns, "at": at}}
	for k, v := range extra {
		doc[k] = v
	}
	return addRoot(doc)
}

// mkRemote creates a remote branch on e (dev mode, or with the operator key).
func (e *tenv) mkRemote(name string, genesis []any) *resp {
	e.t.Helper()
	q := req{method: "PATCH", path: "/ns/" + name, ifNoneMatch: "*", body: genesis, author: "op"}
	if e.auth {
		q.bearer = e.operatorGrant(name)
	}
	return e.do(q)
}

// register sends a remote branch registration to e.
func (e *tenv) register(ns string, remoteNS, at string, ifMatch string, who string) *resp {
	e.t.Helper()
	q := req{method: "POST", path: "/ns/" + ns + "/branches",
		body: map[string]any{"remote": map[string]any{"origin": originB, "ns": remoteNS}, "at": at}}
	if ifMatch == "" {
		q.ifNoneMatch = "*"
	} else if ifMatch != "-" {
		q.ifMatch = ifMatch
	}
	if e.auth {
		q.bearer = who
	} else {
		q.author = who
	}
	return e.do(q)
}

// entries returns a namespace's log as maps.
func (e *tenv) nsLog(ns string, bearer ...string) []map[string]any {
	e.t.Helper()
	var out []map[string]any
	for _, x := range e.get("/ns/"+ns+"/rev/"+e.nsHead(ns, bearer...)+"/log", bearer...).Arr() {
		out = append(out, x.(map[string]any))
	}
	return out
}

func remoteEntries(bl []any) []map[string]any {
	var out []map[string]any
	for _, x := range bl {
		m := x.(map[string]any)
		if _, ok := m["remote"]; ok {
			out = append(out, m)
		}
	}
	return out
}

// Registration, renewal, retries, listing, expiry and prune protection at
// the source (§G.3, §7.4, §8.6).
func TestRemoteRegistration(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA))
	a.mkNS("main", map[string]any{"read": "public"})
	p0 := a.create("main", "p", map[string]any{"n": 0.0})
	p1 := a.appendRev("main", "p", p0, ops(op("replace", "/n", 1.0)))
	at := a.nsHead("main")
	p2 := a.appendRev("main", "p", p1, ops(op("replace", "/n", 2.0)))
	p3 := a.appendRev("main", "p", p2, ops(op("replace", "/n", 3.0)))

	// Preconditions, origins, names and at.
	expectCode(t, a.register("main", "rel", at, "-", "b"), 428, "precondition_required")
	for _, bad := range []map[string]any{
		{"remote": map[string]any{"origin": "http://b.example", "ns": "rel"}, "at": at},
		{"remote": map[string]any{"origin": "https://B.example", "ns": "rel"}, "at": at},
		{"remote": map[string]any{"origin": "https://b.example:443", "ns": "rel"}, "at": at},
		{"remote": map[string]any{"origin": "https://b.example/x", "ns": "rel"}, "at": at},
		{"remote": map[string]any{"origin": originA, "ns": "rel"}, "at": at},
		{"remote": map[string]any{"origin": originB, "ns": "Rel"}, "at": at},
		{"remote": map[string]any{"origin": originB, "ns": "rel"}, "at": hashID(t, "", nil)},
	} {
		r := a.do(req{method: "POST", path: "/ns/main/branches", ifNoneMatch: "*", body: bad, author: "b"})
		expectCode(t, r, 422, "invalid")
	}
	expect(t, a.do(req{method: "POST", path: "/ns/main/branches", ifNoneMatch: "*", author: "b",
		body: map[string]any{"remote": map[string]any{"origin": originB}, "at": at}}), 400)

	before := a.nsHead("main")
	r := a.register("main", "rel", at, "", "b")
	expect(t, r, 201)
	reg1 := r.Str("ns_id")
	if reg1 == "" || r.H.Get("X-Namespace-Revision") != reg1 || a.nsHead("main") != reg1 {
		t.Fatalf("registration %v %s", r.H, r.Body)
	}
	if r.Str("expires") != "2026-11-03T12:00:00.000Z" || r.Str("at") != at {
		t.Fatalf("registration body %s", r.Body)
	}
	// The branch entry with remote (§3.5), hash-verifiable.
	want := map[string]any{"kind": "branch", "remote": map[string]any{"origin": originB, "ns": "rel"}, "at": at}
	lg := a.nsLog("main")
	last := lg[len(lg)-1]
	if last["id"] != hashID(t, before, canonical(want)) || last["name"] != nil || last["target"] != nil {
		t.Fatalf("remote branch entry %v", last)
	}
	// Listed in /branches as { remote, at, ns_id, expires } only.
	bl := a.get("/ns/main/branches").Arr()
	if len(bl) != 1 || string(canonical(bl[0])) != string(canonical(map[string]any{
		"remote": map[string]any{"origin": originB, "ns": "rel"}, "at": at, "ns_id": reg1, "expires": "2026-11-03T12:00:00.000Z"})) {
		t.Fatalf("branches %v", bl)
	}

	// A retry by the same principal gets 200; anyone else 412 with the latest.
	r = a.register("main", "rel", at, "", "b")
	expect(t, r, 200)
	if r.Str("ns_id") != reg1 {
		t.Fatalf("retry %s", r.Body)
	}
	r = a.register("main", "rel", at, "", "c")
	expectCode(t, r, 412, "stale")
	if r.Str("head") != reg1 {
		t.Fatalf("412 %s", r.Body)
	}
	// Another remote is another registration.
	expect(t, a.register("main", "rel2", at, "", "b"), 201)

	// Renewal: If-Match the latest entry, the same at.
	a.clock.Advance(10 * 24 * time.Hour)
	expectCode(t, a.register("main", "rel", before, reg1, "b"), 422, "invalid")
	expectCode(t, a.register("main", "rel", at, hashID(t, "", nil), "b"), 412, "stale")
	r = a.register("main", "rel", at, reg1, "b")
	expect(t, r, 201)
	reg2 := r.Str("ns_id")
	if reg2 == reg1 || r.Str("expires") != "2026-11-13T12:00:00.000Z" {
		t.Fatalf("renewal %s", r.Body)
	}
	// A retry naming the entry before the latest gets the latest, only for
	// the same principal.
	r = a.register("main", "rel", at, reg1, "b")
	expect(t, r, 200)
	if r.Str("ns_id") != reg2 {
		t.Fatalf("renewal retry %s", r.Body)
	}
	expect(t, a.register("main", "rel", at, reg1, "c"), 412)
	if n := len(remoteEntries(anySlice(a.nsLog("main")))); n != 3 {
		t.Fatalf("%d remote entries, want 3", n)
	}

	// Prune protection: the head as of at stays (§8.6).
	a.clock.Advance(10 * time.Minute) // past the retry window
	r = a.prune("main", "p", map[string]any{"horizon": p3}, "admin")
	expect(t, r, 200)
	if r.Str("horizon") != p1 {
		t.Fatalf("horizon with a registration %s, want %s", r.Body, p1)
	}
	expect(t, a.get("/r/main/p/rev/"+p1), 200)
	expectCode(t, a.get("/r/main/p/rev/"+p0), 410, "pruned")

	// After expiry: not listed, not protecting, and registrable again.
	a.clock.Advance(31 * 24 * time.Hour)
	if bl := a.get("/ns/main/branches").Arr(); len(bl) != 0 {
		t.Fatalf("expired registrations listed: %v", bl)
	}
	r = a.prune("main", "p", map[string]any{"horizon": p3}, "admin")
	expect(t, r, 200)
	if r.Str("horizon") != p3 {
		t.Fatalf("horizon after expiry %s", r.Body)
	}
	expect(t, a.register("main", "rel", at, "", "c"), 201)

	// Rate-limited, and not counted as live branches.
	a.mkNS("rl", map[string]any{"limits": map[string]any{"ratePerPrincipal": map[string]any{"rate": 0.001, "burst": 1.0}, "branchesPerNamespace": 0.0}})
	rlAt := a.nsHead("rl")
	expect(t, a.register("rl", "x", rlAt, "", "b"), 201)
	expectCode(t, a.register("rl", "y", rlAt, "", "b"), 429, "rate")
}

func anySlice(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

// Registration needs read and export and is checked as an export envelope.
func TestRemoteRegistrationAuth(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil, withOrigin(originA))
	at := f.nsHead("sec", f.adminG)
	readOnly := f.grant(f.admin, "user:b", []string{"sec"}, []string{"read"})
	exportOnly := f.grant(f.admin, "user:b", []string{"sec"}, []string{"export"})
	both := f.grant(f.admin, "user:b", []string{"sec"}, []string{"read", "export"})
	onlyRel := f.grant(f.admin, "user:b", []string{"sec"}, []string{"read", "export"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/doc/remote/ns", "value": "rel"}}})
	issuer := f.grant(f.issuer, "user:b", []string{"sec"}, []string{"read", "export"})

	expectCode(t, f.register("sec", "rel", at, "", readOnly), 403, "forbidden")
	expectCode(t, f.register("sec", "rel", at, "", exportOnly), 403, "forbidden")
	expect(t, f.register("sec", "rel", at, "", issuer), 403) // the key's scope has no export
	expectCode(t, f.register("sec", "other", at, "", onlyRel), 403, "forbidden")
	expect(t, f.register("sec", "rel", at, "", onlyRel), 201)
	expect(t, f.register("sec", "rel2", at, "", both), 201)
	// /branches needs read.
	expect(t, f.get("/ns/sec/branches"), 401)
	if n := len(f.get("/ns/sec/branches", both).Arr()); n != 2 {
		t.Fatalf("%d listed", n)
	}
}

// populateA fills A with a schema namespace and a base namespace, and
// returns at and the ids B must reproduce.
type aFixture struct {
	at                  string
	s1, s2              string // schema revisions
	d1, d2              string // derby
	o1                  string // old: typed with s1
	b1, bt              string // b, tombstoned at at
	c1                  string // c, purged before at
	lateD, lateResource string
}

func populateA(t *testing.T, a *tenv) aFixture {
	t.Helper()
	var f aFixture
	a.mkNS("schemas", map[string]any{"read": "public"})
	f.s1 = a.create("schemas", "match", matchSchema())
	f.s2 = a.appendRev("schemas", "match", f.s1, ops(op("add", "/properties/venue", map[string]any{"type": "string"})))
	a.mkNS("main", map[string]any{"read": "public", "x-title": "A's main"})
	f.d1 = a.create("main", "derby", map[string]any{"$schema": "/r/schemas/match/rev/" + f.s2, "score": "0-0"})
	f.d2 = a.appendRev("main", "derby", f.d1, ops(op("replace", "/score", "1-0")))
	f.o1 = a.create("main", "old", map[string]any{"$schema": "/r/schemas/match/rev/" + f.s1, "score": "2-2"})
	f.b1 = a.create("main", "b", map[string]any{"b": true})
	f.bt = a.del("main", "b", f.b1)
	f.c1 = a.create("main", "c", map[string]any{"secret": true})
	expect(t, a.purge("main", "c", f.c1, "admin"), 204)
	r := a.do(req{method: "POST", path: "/ns/main/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "e", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"e": 1.0})}},
		map[string]any{"resource": "f", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"f": 1.0}), ops(op("add", "/g", 2.0))}},
	}}})
	expect(t, r, 201)
	f.at = a.nsHead("main")
	// Changes at A after at.
	f.lateD = a.appendRev("main", "derby", f.d2, ops(op("replace", "/score", "5-0")))
	f.lateResource = a.create("main", "late", map[string]any{})
	return f
}

// Creating a remote branch mirrors and verifies A as of at; B reads through,
// writes with foreign parents into the mirrored chain, and never sees A's
// later changes (§G.3, §7.6).
func TestRemoteBranch(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	f := populateA(t, a)

	// A genesis without an operator-level base is rejected; so is our own origin.
	bad := addRoot(map[string]any{"base": map[string]any{"origin": originB, "ns": "main", "at": f.at}})
	expectCode(t, b.mkRemote("rel", bad), 422, "invalid")
	bad = addRoot(map[string]any{"base": map[string]any{"origin": "http://a.example", "ns": "main", "at": f.at}})
	expectCode(t, b.mkRemote("rel", bad), 422, "invalid")
	// An at not in A's chain.
	expectCode(t, b.mkRemote("rel", remoteGenesis("main", hashID(t, "", nil), nil)), 422, "invalid")
	expect(t, b.get("/ns/rel"), 404)

	r := b.mkRemote("rel", remoteGenesis("main", f.at, map[string]any{"x-title": "B's release"}))
	expect(t, r, 201)
	// Its document is B's own; its log only its own config entry.
	doc := b.get("/ns/rel/rev/" + b.nsHead("rel")).Obj()
	if doc["x-title"] != "B's release" || doc["base"].(map[string]any)["origin"] != originA {
		t.Fatalf("remote branch document %v", doc)
	}
	if k := b.nsKinds("rel"); len(k) != 1 || k[0] != "config" {
		t.Fatalf("remote branch log %v", k)
	}
	// Taken now.
	expect(t, b.mkRemote("rel", remoteGenesis("main", f.at, nil)), 412)
	// The shadow can't be addressed.
	expect(t, b.get("/ns/~rel"), 400)
	expect(t, b.get("/r/~rel/derby"), 400)

	// Read-through, with A's ids.
	if h := b.head("rel", "derby"); h != f.d2 {
		t.Fatalf("derby head %s, want %s", h, f.d2)
	}
	for _, name := range []string{"derby", "old", "e", "f"} {
		want := headAt(t, a, "main", f.at, name)
		if got := b.head("rel", name); got != want {
			t.Fatalf("%s: head %s, want %s", name, got, want)
		}
		if string(canonical(b.get("/r/rel/"+name+"/rev/"+want).JSON())) != string(canonical(a.get("/r/main/"+name+"/rev/"+want).JSON())) {
			t.Fatalf("%s: documents differ", name)
		}
		la := a.get("/r/main/" + name + "/rev/" + want + "/log").Body
		lb := b.get("/r/rel/" + name + "/rev/" + want + "/log").Body
		if !bytes.Equal(la, lb) {
			t.Fatalf("%s: logs differ\nA %s\nB %s", name, la, lb)
		}
	}
	expect(t, b.get("/r/rel/derby/rev/"+f.d1), 200)
	g := b.get("/r/rel/b")
	expectCode(t, g, 410, "gone")
	if g.Str("tombstone") != f.bt || g.Str("last") != f.b1 {
		t.Fatalf("tombstoned read-through %s", g.Body)
	}
	expect(t, b.get("/r/rel/c"), 410)                  // purged at A before at
	expect(t, b.get("/r/rel/c/rev/"+f.c1), 410)        // and its content isn't here
	expect(t, b.get("/r/rel/late"), 404)               // created after at
	expect(t, b.get("/r/rel/derby/rev/"+f.lateD), 404) // appended after at
	hb := b.get("/ns/rel/rev/" + b.nsHead("rel") + "/heads").Obj()["items"]
	ha := a.get("/ns/main/rev/" + f.at + "/heads").Obj()["items"]
	if string(canonical(hb)) != string(canonical(ha)) {
		t.Fatalf("heads differ\nA %s\nB %s", canonical(ha), canonical(hb))
	}

	// Schemas are mirrored under the same paths into a non-branch namespace.
	if h := b.head("schemas", "match"); h != f.s2 {
		t.Fatalf("mirrored schema head %s", h)
	}
	expect(t, b.get("/r/schemas/match/rev/"+f.s1), 200)
	if lb, la := b.get("/r/schemas/match/rev/"+f.s2+"/log").Body, a.get("/r/schemas/match/rev/"+f.s2+"/log").Body; !bytes.Equal(la, lb) {
		t.Fatalf("schema logs differ")
	}

	// First write: the precondition is A's head as of at, the parent foreign.
	r = b.write("PATCH", "rel", "derby", f.lateD, ops(op("replace", "/score", "9-9")))
	expectCode(t, r, 412, "stale")
	if r.Str("head") != f.d2 {
		t.Fatalf("412 %s", r.Body)
	}
	expectCode(t, b.write("PATCH", "rel", "derby", f.d2, ops(op("replace", "/score", 3.0))), 422, "invalid") // B validates with the mirrored schema
	patches := ops(op("replace", "/score", "2-0"))
	w := b.appendRev("rel", "derby", f.d2, patches)
	if w != hashID(t, f.d2, canonical(patches)) {
		t.Fatal("the foreign parent was not used")
	}
	lg := b.get("/r/rel/derby/rev/" + w + "/log").Arr()
	if len(lg) != 3 || lg[0].(map[string]any)["id"] != f.d1 || lg[2].(map[string]any)["parent"] != f.d2 {
		t.Fatalf("log across the foreign parent %v", lg)
	}
	if b.doc("rel", "derby")["score"] != "2-0" {
		t.Fatal("document after the first write")
	}
	// Restoring a mirrored tombstone, and creating a name A made after at.
	b.appendRev("rel", "b", f.bt, []any{})
	b.create("rel", "late", map[string]any{"mine": true})
	// A is untouched, and A's later changes are still invisible.
	if a.head("main", "derby") != f.lateD || a.doc("main", "late")["mine"] != nil {
		t.Fatal("A changed")
	}
	if b.head("rel", "old") != f.o1 {
		t.Fatal("old")
	}
	// Local branches of the remote branch work as usual.
	expect(t, b.branch("rel", map[string]any{"name": "rel-b"}, "alice"), 201)
	if b.head("rel-b", "derby") != w || b.head("rel-b", "e") != headAt(t, a, "main", f.at, "e") {
		t.Fatal("branch of a remote branch")
	}
	// Mirrored schemas protect themselves from purge like local ones.
	expectCode(t, b.purge("schemas", "match", f.s2, "alice"), 409, "in_use")
	// B can't purge A's schema namespace or A's base: they're B's own names.
	if a.head("schemas", "match") != f.s2 {
		t.Fatal("A's schema")
	}

	// Survives a cache flush: documents fold from storage.
	b.e.FlushCaches()
	if b.doc("rel", "e")["e"] != 1.0 || b.doc("rel", "f")["g"] != 2.0 {
		t.Fatal("after flush")
	}
}

func headAt(t *testing.T, e *tenv, ns, at, name string) string {
	t.Helper()
	for _, x := range e.get("/ns/" + ns + "/rev/" + at + "/heads").Obj()["items"].([]any) {
		m := x.(map[string]any)
		if m["resource"] == name {
			s, _ := m["target"].(string)
			return s
		}
	}
	t.Fatalf("%s not in heads", name)
	return ""
}

// A schema path holding a different history is 409 name_conflict; a prefix
// is extended; nothing is written on failure.
func TestRemoteSchemaConflict(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, nil)
	f := populateA(t, a)

	b.mkNS("schemas", map[string]any{"read": "public"})
	other := b.create("schemas", "match", map[string]any{"$schema": dialect, "type": "object"})
	r := b.mkRemote("rel", remoteGenesis("main", f.at, nil))
	expectCode(t, r, 409, "name_conflict")
	if !strings.Contains(r.Str("path"), "/r/schemas/match/rev/") {
		t.Fatalf("conflict body %s", r.Body)
	}
	expect(t, b.get("/ns/rel"), 404)
	if b.head("schemas", "match") != other {
		t.Fatal("conflicting schema changed")
	}

	// A prefix of A's chain is extended; a namespace holding it as a branch conflicts.
	b2 := newEnv(t, withOrigin(originB), withRemote(rt))
	b2.mkNS("schemas", map[string]any{"read": "public"})
	if id := b2.create("schemas", "match", matchSchema()); id != f.s1 {
		t.Fatalf("same genesis, different id %s", id)
	}
	before := len(b2.nsKinds("schemas"))
	expect(t, b2.mkRemote("rel", remoteGenesis("main", f.at, nil)), 201)
	if b2.head("schemas", "match") != f.s2 {
		t.Fatal("prefix not extended")
	}
	if k := b2.nsKinds("schemas"); len(k) != before+1 || lastOf(k) != "batch" {
		t.Fatalf("schema namespace log %v", k)
	}
	// Already containing A's chain: nothing to do.
	expect(t, b2.mkRemote("rel2", remoteGenesis("main", f.at, nil)), 201)
	if k := b2.nsKinds("schemas"); len(k) != before+1 {
		t.Fatalf("schema namespace log after a second branch %v", k)
	}

	// A remote branch can't take the name of a namespace its schemas need.
	b4 := newEnv(t, withOrigin(originB), withRemote(rt))
	expectCode(t, b4.mkRemote("schemas", remoteGenesis("main", f.at, nil)), 409, "name_conflict")
	expect(t, b4.get("/ns/schemas"), 404)

	b3 := newEnv(t, withOrigin(originB), withRemote(rt))
	b3.mkNS("base", map[string]any{"read": "public"})
	expect(t, b3.branch("base", map[string]any{"name": "schemas"}, "alice"), 201)
	expectCode(t, b3.mkRemote("rel", remoteGenesis("main", f.at, nil)), 409, "name_conflict")
}

// tamper serves A through a proxy that rewrites responses whose path
// matches.
func tamper(t *testing.T, a *tenv, match string, rewrite func([]byte) []byte) string {
	t.Helper()
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hr, _ := http.NewRequest(r.Method, a.srv.URL+r.URL.RequestURI(), r.Body)
		hr.Header = r.Header.Clone()
		res, err := client.Do(hr)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if strings.Contains(r.URL.Path, match) {
			body = rewrite(body)
		}
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

// Source data that fails verification is refused, and nothing is written.
func TestRemoteTampered(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, nil)
	f := populateA(t, a)
	cases := []struct {
		name, match, from, to string
	}{
		{"resource log", "/r/main/derby/rev/", `"1-0"`, `"7-0"`},
		{"schema log", "/r/schemas/match/rev/", `venue`, `vanue`},
		{"namespace log", "/ns/main/rev/" + f.at + "/log", `"resource":"old"`, `"resource":"odl"`},
		{"heads", "/heads", `"resource":"e"`, `"resource":"x"`},
	}
	for _, c := range cases {
		rt.set(tamper(t, a, c.match, func(b []byte) []byte { return bytes.ReplaceAll(b, []byte(c.from), []byte(c.to)) }), "")
		r := b.mkRemote("rel", remoteGenesis("main", f.at, nil))
		if r.Code != 502 || r.Str("code") != "remote" {
			t.Errorf("%s: %d %s", c.name, r.Code, r.Body)
		}
		expect(t, b.get("/ns/rel"), 404)
		expect(t, b.get("/ns/schemas"), 404)
	}
	// Unreachable: 502.
	rt.set("http://127.0.0.1:1", "")
	expectCode(t, b.mkRemote("rel", remoteGenesis("main", f.at, nil)), 502, "remote")
	// Genuine data through the same proxy works.
	rt.set(tamper(t, a, "/nothing", nil), "")
	expect(t, b.mkRemote("rel", remoteGenesis("main", f.at, nil)), 201)
}

// Keys and revocations don't reach across (§7.6, §G.3): A's grants give
// nothing at B, B's keys are its own, and a private base's branch can't be
// public.
func TestRemoteKeys(t *testing.T) {
	t.Parallel()
	var aPriv, bPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv))
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("main", map[string]any{"read": "grant", "keys": []any{kA.entry("*")}})
	gA := a.grant(kA, "user:a", []string{"main", "rel"}, []string{"read", "create", "append", "export"})
	d := a.create("main", "d", map[string]any{"v": 1.0}, gA)
	at := a.nsHead("main", gA)

	rt := &route{url: a.srv.URL}
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt))
	b.opPriv = bPriv
	// Without a read grant at A, the base can't be fetched.
	expectCode(t, b.mkRemote("rel", remoteGenesis("main", at, map[string]any{"read": "grant"})), 502, "remote")
	rt.set(a.srv.URL, a.grant(kA, "svc:b", []string{"main"}, []string{"read"}))
	// Only the operator key creates remote branches.
	q := req{method: "PATCH", path: "/ns/rel", ifNoneMatch: "*", body: remoteGenesis("main", at, nil), bearer: gA}
	expect(t, b.do(q), 401)
	// A private base's branch can't be public (§G.5).
	expectCode(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 422, "invalid")
	kB := newKey("admin") // same kid, B's own key
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})), 201)

	// A's grant, even with a matching kid, is nothing at B.
	expect(t, b.get("/r/rel/d", gA), 401)
	expect(t, b.write("PATCH", "rel", "d", d, ops(op("replace", "/v", 2.0)), gA), 401)
	gB := b.grant(kB, "user:b", []string{"rel"}, []string{"read", "append", "config"})
	if b.head("rel", "d", gB) != d {
		t.Fatal("read-through with B's grant")
	}
	w := b.appendRev("rel", "d", d, ops(op("replace", "/v", 2.0)), gB)
	// Removing the key at A changes nothing at B; B's keys can change freely.
	kA2 := newKey("admin2")
	expect(t, a.patchNS("main", ops(op("replace", "/keys", []any{kA2.entry("*")})), a.grant(kA, "user:root", []string{"main"}, []string{"config", "read"})), 201)
	if b.head("rel", "d", gB) != w {
		t.Fatal("B's grant stopped working")
	}
	// B's revocations are its own.
	expect(t, b.patchNS("rel", ops(op("add", "/revoked", []any{revocationID(t, gB, 0)})), b.grant(kB, "user:root", []string{"rel"}, []string{"config", "read"})), 201)
	if g := b.get("/r/rel/d", gB); g.Code == 302 {
		t.Fatal("revoked grant still reads")
	}
}

// A's purges reach B as notices from A's log (§G.3), applied by default.
func TestRemotePurgeFollowed(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	f := populateA(t, a)
	expect(t, b.mkRemote("rel", remoteGenesis("main", f.at, nil)), 201)
	w := b.appendRev("rel", "derby", f.d2, ops(op("replace", "/score", "2-0")))
	expect(t, b.branch("rel", map[string]any{"name": "rel-b"}, "alice"), 201)
	ctx := context.Background()
	if err := b.e.SyncRemotes(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := b.e.RemoteNotices(ctx, "rel"); len(n) != 0 {
		t.Fatalf("notices before any purge %v", n)
	}

	expect(t, a.purge("main", "derby", f.lateD, "admin"), 204)
	expect(t, a.purge("main", "e", headAt(t, a, "main", f.at, "e"), "admin"), 204)
	if err := b.e.SyncRemotes(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/r/rel/derby", "/r/rel/derby/rev/" + w, "/r/rel/derby/rev/" + f.d1, "/r/rel-b/derby", "/r/rel/e", "/r/rel-b/e"} {
		if g := b.get(p); g.Code != 410 {
			t.Errorf("%s after A's purge: %d %s", p, g.Code, g.Body)
		}
	}
	if k := b.nsKinds("rel"); lastOf(k) != "purge" || k[len(k)-2] != "purge" {
		t.Fatalf("remote branch log %v", k)
	}
	if lastOf(b.nsKinds("rel-b")) != "purge" {
		t.Fatalf("local branch log %v", b.nsKinds("rel-b"))
	}
	ns, err := b.e.RemoteNotices(ctx, "rel")
	if err != nil || len(ns) != 2 || !ns[0].Applied || ns[0].Kind != "purge" || ns[0].Resource != "derby" {
		t.Fatalf("notices %+v %v", ns, err)
	}
	// Following again changes nothing.
	head := b.nsHead("rel")
	if err := b.e.SyncRemotes(ctx); err != nil || b.nsHead("rel") != head {
		t.Fatalf("second sync: %v", err)
	}
	if b.head("rel", "old") != f.o1 {
		t.Fatal("unpurged resource")
	}

	// A's namespace purge: every name A had is purged here, B's own names stay.
	b.create("rel", "mine", map[string]any{})
	expect(t, a.patchNS("main", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, a.do(req{method: "POST", path: "/ns/main/purge", ifMatch: a.nsHead("main"), author: "admin"}), 204)
	if err := b.e.SyncRemotes(ctx); err != nil {
		t.Fatal(err)
	}
	expect(t, b.get("/r/rel/old"), 410)
	expect(t, b.get("/r/rel/f"), 410)
	expect(t, b.get("/r/rel/mine"), 302)
}

// With IgnorePurges, A's purges are recorded as notices only.
func TestRemotePurgeNotFollowed(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil, func(o *core.RemoteOptions) { o.IgnorePurges = true })
	f := populateA(t, a)
	expect(t, b.mkRemote("rel", remoteGenesis("main", f.at, nil)), 201)
	expect(t, a.purge("main", "derby", f.lateD, "admin"), 204)
	ctx := context.Background()
	if err := b.e.SyncRemotes(ctx); err != nil {
		t.Fatal(err)
	}
	if b.head("rel", "derby") != f.d2 {
		t.Fatal("purge applied")
	}
	ns, _ := b.e.RemoteNotices(ctx, "")
	if len(ns) != 1 || ns[0].Applied || ns[0].Branch != "rel" || ns[0].Resource != "derby" {
		t.Fatalf("notices %+v", ns)
	}
	// The operator follows it with an ordinary purge.
	expect(t, b.purge("rel", "derby", f.d2, "op"), 204)
	expect(t, b.get("/r/rel/derby/rev/"+f.d1), 410)
}

// B's namespace purge needs nothing from A and changes nothing there; a
// remote registration never blocks A's namespace purge; local dependents
// still block (§7.6, §8.5).
func TestRemoteNamespacePurge(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, nil)
	f := populateA(t, a)
	expect(t, b.mkRemote("rel", remoteGenesis("main", f.at, nil)), 201)
	expect(t, b.branch("rel", map[string]any{"name": "rel-b"}, "alice"), 201)
	rt.set("http://127.0.0.1:1", "") // A unreachable from now on
	expect(t, b.patchNS("rel", ops(op("add", "/frozen", true)), ""), 201)
	nspurge := func(e *tenv, ns string) *resp {
		return e.do(req{method: "POST", path: "/ns/" + ns + "/purge", ifMatch: e.nsHead(ns), author: "admin"})
	}
	expectCode(t, nspurge(b, "rel"), 409, "in_use")
	expect(t, b.patchNS("rel-b", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, nspurge(b, "rel-b"), 204)
	expect(t, nspurge(b, "rel"), 204)
	expect(t, b.get("/r/rel/derby"), 410)
	expect(t, b.get("/r/rel/derby/rev/"+f.d1), 410)
	if a.head("main", "derby") != f.lateD {
		t.Fatal("A changed")
	}
	// The name stays reserved.
	expect(t, b.mkRemote("rel", remoteGenesis("main", f.at, nil)), 412)
	// Mirrored schemas are unreferenced now and can be purged.
	expect(t, b.purge("schemas", "match", f.s2, "alice"), 204)

	// A registered branch doesn't block A.
	expect(t, a.register("main", "rel", f.at, "", "b"), 201)
	expect(t, a.patchNS("main", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, nspurge(a, "main"), 204)
}

// B registers its remote branch with A and renews before expiry (§G.3).
func TestRemoteRegisterAndRenew(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil, func(o *core.RemoteOptions) { o.Register = true })
	f := populateA(t, a)
	expect(t, b.mkRemote("rel", remoteGenesis("main", f.at, nil)), 201)
	bl := a.get("/ns/main/branches").Arr()
	if len(bl) != 1 || string(canonical(bl[0].(map[string]any)["remote"])) != string(canonical(map[string]any{"origin": originB, "ns": "rel"})) {
		t.Fatalf("A's branches %v", bl)
	}
	reg1 := bl[0].(map[string]any)["ns_id"]
	ctx := context.Background()
	// Not yet due.
	if err := b.e.SyncRemotes(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(remoteEntries(anySlice(a.nsLog("main")))); n != 1 {
		t.Fatalf("%d registrations", n)
	}
	// Within RenewBefore of expiry: renewed with If-Match.
	b.clock.Advance(24 * 24 * time.Hour)
	a.clock.Advance(24 * 24 * time.Hour)
	if err := b.e.SyncRemotes(ctx); err != nil {
		t.Fatal(err)
	}
	bl = a.get("/ns/main/branches").Arr()
	if len(bl) != 1 || bl[0].(map[string]any)["ns_id"] == reg1 || bl[0].(map[string]any)["expires"] != "2026-11-27T12:00:00.000Z" {
		t.Fatalf("after renewal %v", bl)
	}
	if n := len(remoteEntries(anySlice(a.nsLog("main")))); n != 2 {
		t.Fatalf("%d registrations", n)
	}
}

// History pruned at A is mirrored from the horizon, its document a snapshot
// (§8.6, §G.3).
func TestRemotePrunedBase(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	a.mkNS("main", map[string]any{"read": "public"})
	revs := a.chain("main", "p", 5)
	a.clock.Advance(10 * time.Minute)
	r := a.prune("main", "p", map[string]any{"horizon": revs[3]}, "admin")
	expect(t, r, 200)
	if r.Str("horizon") != revs[3] {
		t.Fatalf("prune %s", r.Body)
	}
	at := a.nsHead("main")
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 201)
	if b.head("rel", "p") != revs[4] || b.doc("rel", "p")["n"] != 4.0 {
		t.Fatal("read-through from a horizon")
	}
	expect(t, b.get("/r/rel/p/rev/"+revs[3]), 200)
	if g := b.get("/r/rel/p/rev/" + revs[1]); g.Code == 200 {
		t.Fatal("pruned revision served")
	}
	expectCode(t, b.get("/r/rel/p/rev/"+revs[4]+"/log"), 410, "pruned")
	lg := b.get("/r/rel/p/rev/" + revs[4] + "/log?since=" + revs[3]).Arr()
	if len(lg) != 1 || lg[0].(map[string]any)["id"] != revs[4] {
		t.Fatalf("log from the horizon %v", lg)
	}
	w := b.appendRev("rel", "p", revs[4], ops(op("replace", "/n", 5.0)))
	b.e.FlushCaches()
	if b.doc("rel", "p")["n"] != 5.0 || b.head("rel", "p") != w {
		t.Fatal("write on a mirrored horizon")
	}
}
