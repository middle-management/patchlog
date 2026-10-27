package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// delegated narrows a root grant twice, by svc:a and then svc:b: its
// principal's via is [svc:a, svc:b] (§C.1).
func delegated(t *testing.T, e *tenv, k keyPair, sub string, ns []string, can []string) string {
	t.Helper()
	root := map[string]any{"kid": k.kid, "sub": sub, "ns": strs(ns), "can": strs(can), "exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}
	g, err := grant.Mint(root, k.priv)
	if err != nil {
		t.Fatal(err)
	}
	if g, err = g.Narrow(map[string]any{"via": "svc:a"}); err != nil {
		t.Fatal(err)
	}
	if g, err = g.Narrow(map[string]any{"via": "svc:b"}); err != nil {
		t.Fatal(err)
	}
	return g.Encode()
}

// viaOf is an entry's via member, nil where it is absent.
func viaOf(t *testing.T, m map[string]any) []string {
	t.Helper()
	v, has := m["via"]
	if !has {
		return nil
	}
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		t.Fatalf("via %v: not a non-empty array (absent when there are none, §7.1)", v)
	}
	out := make([]string, len(arr))
	for i, x := range arr {
		out[i] = x.(string)
	}
	return out
}

// §7.1, §7.4, §C.1 (RH-7, RH-8, CIS-35): resource and namespace log entries
// carry via, the delegatees of the grant they were written under in order,
// absent when there are none: in ranges, long-poll answers and events. It
// is unhashed: the entry's id doesn't cover it.
func TestV073EntriesCarryVia(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil, withLongPoll(100*time.Millisecond))
	e := f.tenv
	can := []string{"read", "create", "append", "delete", "config"}
	dg := delegated(t, e, f.issuer, "user:bob", []string{"sec"}, can)
	want := []string{"svc:a", "svc:b"}

	a1 := e.create("sec", "a", map[string]any{"n": 1.0}, dg)
	a2 := e.appendRev("sec", "a", a1, ops(op("replace", "/n", 2.0)), f.issuerG)
	lg := e.get("/r/sec/a/rev/"+a2+"/log", f.issuerG).Arr()
	if len(lg) != 2 {
		t.Fatalf("log %v", lg)
	}
	if got := viaOf(t, lg[0].(map[string]any)); !slices.Equal(got, want) {
		t.Errorf("delegated revision via %v, want %v", got, want)
	}
	if got := viaOf(t, lg[1].(map[string]any)); got != nil {
		t.Errorf("undelegated revision via %v, want none", got)
	}
	// A tombstone too.
	tomb := e.del("sec", "a", a2, dg)
	lg = e.get("/r/sec/a/rev/"+tomb+"/log?since="+a2, f.issuerG).Arr()
	if len(lg) != 1 || !slices.Equal(viaOf(t, lg[0].(map[string]any)), want) {
		t.Errorf("tombstone entry %v, want via %v", lg, want)
	}
	// A long-poll answer.
	lp := e.get("/r/sec/a/log?live=long-poll&since="+a1, f.issuerG)
	expect(t, lp, 200)
	if la := lp.Arr(); len(la) != 2 || viaOf(t, la[0].(map[string]any)) != nil || !slices.Equal(viaOf(t, la[1].(map[string]any)), want) {
		t.Errorf("resource long-poll %s", lp.Body)
	}

	// Namespace entries: a single write, a config write and a batch.
	cr := e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: e.configID("sec", f.issuerG), body: ops(op("add", "/x-note", "n")), bearer: dg})
	expect(t, cr, 201)
	br := e.do(req{method: "POST", path: "/ns/sec/batch", bearer: dg, body: map[string]any{"items": []any{
		map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"n": 1.0})}},
		map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"n": 1.0})}},
	}}})
	expect(t, br, 201)
	head := e.nsHead("sec", f.issuerG)
	nl := e.get("/ns/sec/rev/"+head+"/log", f.issuerG).Arr()
	byKind := map[string][][]string{}
	for _, x := range nl {
		m := x.(map[string]any)
		k := m["kind"].(string)
		if k == "head" && m["resource"] == "a" && m["target"] == a2 {
			k = "head-undelegated"
		}
		byKind[k] = append(byKind[k], viaOf(t, m))
		// Unhashed: the id is the hash of the previous id and the body
		// without author, via, created, grant and gestures (§3.5).
		body := map[string]any{}
		for key, v := range m {
			switch key {
			case "id", "prev", "author", "via", "created", "grant", "gesture", "undoes", "gestures":
			default:
				body[key] = v
			}
		}
		prev, _ := m["prev"].(string)
		if id := hashID(t, prev, jsonv.Canonical(body)); id != m["id"] {
			t.Fatalf("entry %v: id isn't the hash of its body without via", m)
		}
	}
	for kind, wantVia := range map[string][]string{"head": want, "tombstone": want, "config": want, "batch": want, "head-undelegated": nil} {
		got := byKind[kind]
		if len(got) == 0 {
			t.Errorf("no %s entry in %v", kind, nl)
			continue
		}
		if g := got[len(got)-1]; !slices.Equal(g, wantVia) {
			t.Errorf("%s entry via %v, want %v", kind, g, wantVia)
		}
	}
	// The namespace's genesis, written by the operator, has none.
	if g := byKind["config"][0]; g != nil {
		t.Errorf("genesis via %v, want none", g)
	}
	// Namespace long-poll answers and events serve it alike.
	since := nl[len(nl)-2].(map[string]any)["id"].(string)
	nlp := e.get("/ns/sec/log?live=long-poll&since="+since, f.issuerG)
	expect(t, nlp, 200)
	if arr := nlp.Arr(); len(arr) != 1 || !slices.Equal(viaOf(t, arr[0].(map[string]any)), want) {
		t.Errorf("namespace long-poll %s", nlp.Body)
	}
	ch, _, cancel := e.openSSE("/ns/sec/events?since="+since, map[string]string{"Authorization": "Bearer " + f.issuerG})
	ev := next(t, ch)
	cancel()
	if m, _ := jsonv.MustParse([]byte(ev.data)).(map[string]any); ev.event != "batch" || !slices.Equal(viaOf(t, m), want) {
		t.Errorf("namespace event %v", ev)
	}
	rch, _, rcancel := e.openSSE("/r/sec/b/events", map[string]string{"Authorization": "Bearer " + f.issuerG})
	rev := next(t, rch)
	rcancel()
	if m, _ := jsonv.MustParse([]byte(rev.data)).(map[string]any); rev.event != "revision" || !slices.Equal(viaOf(t, m), want) {
		t.Errorf("revision event %v", rev)
	}
}

// §7.4, §8.3 (RH-8): entries the server writes itself, such as a purge it
// propagates into a branch, record no via, whoever caused them.
func TestV073ServerEntriesHaveNoVia(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	all := []string{"read", "create", "append", "delete", "config", "branch", "purge"}
	dg := delegated(t, e, f.admin, "user:root", []string{"sec", "sec-b"}, all)
	a := e.create("sec", "a", map[string]any{"n": 1.0}, dg)
	expect(t, e.do(req{method: "POST", path: "/ns/sec/branches", ifNoneMatch: "*", bearer: dg, body: map[string]any{"name": "sec-b"}}), 201)
	expect(t, e.do(req{method: "POST", path: "/r/sec/a/purge", ifMatch: a, bearer: dg}), 204)
	nl := e.get("/ns/sec/rev/"+e.nsHead("sec", f.adminG)+"/log", f.adminG).Arr()
	last := nl[len(nl)-1].(map[string]any)
	if last["kind"] != "purge" || !slices.Equal(viaOf(t, last), []string{"svc:a", "svc:b"}) {
		t.Errorf("the requested purge %v, want via", last)
	}
	bl := e.get("/ns/sec-b/rev/"+e.nsHead("sec-b", f.adminG)+"/log", f.adminG).Arr()
	var found bool
	for _, x := range bl {
		m := x.(map[string]any)
		switch m["kind"] {
		case "branch":
			if !slices.Equal(viaOf(t, m), []string{"svc:a", "svc:b"}) {
				t.Errorf("branch creation entry %v, want via", m)
			}
		case "purge":
			found = true
			if _, has := m["via"]; has {
				t.Errorf("propagated purge %v carries via", m)
			}
		}
	}
	if !found {
		t.Fatalf("no propagated purge in %v", bl)
	}
}

// §7.1, §E.2.2 (RH-7): at E2 via is inside the sealed entry.
func TestV073SealedEntryCarriesVia(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k := newKey("issuer")
	r := e.do(req{method: "PATCH", path: "/ns/s", ifNoneMatch: "*", bearer: e.operatorGrant("s"),
		body: addRoot(sealedDoc(map[string]any{"read": "public", "keys": []any{k.entry("read", "create", "append")}}))})
	expect(t, r, 201)
	dg := delegated(t, e, k, "user:bob", []string{"s"}, []string{"read", "create", "append"})
	id := e.wr("s", "x", "", withNonce(addRoot(map[string]any{"n": 1.0})), dg)
	keys, kr := e.keysOf("s", nil, dg)
	expect(t, kr, 200)
	ke := keys["s#1"]
	lg := e.get("/r/s/x/rev/" + id + "/log")
	expect(t, lg, 200)
	arr := lg.Arr()
	if len(arr) != 1 {
		t.Fatalf("log %s", lg.Body)
	}
	pt := open(t, arr[0].(string), resKey(t, ke, "s", "x"), "s#1", seal.ResourcePL("s", "x", id, "rev"))
	if m := jsonv.MustParse(pt).(map[string]any); !slices.Equal(viaOf(t, m), []string{"svc:a", "svc:b"}) {
		t.Errorf("sealed entry %s, want via", pt)
	}
	head := e.nsHead("s")
	rr := e.get("/ns/s/rev/" + head + "/log")
	expect(t, rr, 200)
	pt = open(t, string(rr.Body), ke, "s#1", seal.RangePL("s", "", head))
	entries := jsonv.MustParse(pt).([]any)
	if m := entries[len(entries)-1].(map[string]any); !slices.Equal(viaOf(t, m), []string{"svc:a", "svc:b"}) {
		t.Errorf("sealed namespace entry %v, want via", m)
	}
}

// §7.1, §G.3 (RH-7): a remote branch mirrors its base's entries with their
// via, and serves them as the base does.
func TestV073RemoteMirrorCopiesVia(t *testing.T) {
	t.Parallel()
	a := newAuthFixture(t, map[string]any{"read": "public"}, withOrigin(originA)).tenv
	rt := &route{url: a.srv.URL}
	b := newEnv(t, withOrigin(originB), withRemote(rt))
	issuer := newKey("issuer2")
	expect(t, a.do(req{method: "PATCH", path: "/ns/n", ifNoneMatch: "*", bearer: a.operatorGrant("n"),
		body: addRoot(map[string]any{"read": "public", "keys": []any{issuer.entry("read", "create", "append")}})}), 201)
	dg := delegated(t, a, issuer, "user:bob", []string{"n"}, []string{"read", "create", "append"})
	x1 := a.create("n", "x", map[string]any{"n": 1.0}, dg)
	x2 := a.appendRev("n", "x", x1, ops(op("replace", "/n", 2.0)), a.grant(issuer, "user:bob", []string{"n"}, []string{"append"}))
	at := a.nsHead("n")
	expect(t, b.mkRemote("rel", remoteGenesis("n", at, nil)), 201)
	lg := b.get("/r/rel/x/rev/" + x2 + "/log").Arr()
	if len(lg) != 2 {
		t.Fatalf("mirrored log %v", lg)
	}
	if got := viaOf(t, lg[0].(map[string]any)); !slices.Equal(got, []string{"svc:a", "svc:b"}) {
		t.Errorf("mirrored delegated entry via %v", got)
	}
	if got := viaOf(t, lg[1].(map[string]any)); got != nil {
		t.Errorf("mirrored undelegated entry via %v", got)
	}
}

// §7.4, §7.1 Continuations (RH-10): /heads answers { heads, next? }, next
// the following page's after, absent on the last.
func TestV073HeadsShape(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withLogPageSize(2))
	e.mkNS("m", map[string]any{"read": "public"})
	for _, n := range []string{"a", "b", "c"} {
		e.create("m", n, map[string]any{})
	}
	head := e.nsHead("m")
	r := e.get("/ns/m/rev/" + head + "/heads")
	expect(t, r, 200)
	m := r.Obj()
	if _, has := m["items"]; has {
		t.Fatalf("heads page %s carries items", r.Body)
	}
	if hs, _ := m["heads"].([]any); len(hs) != 2 || m["next"] != "b" {
		t.Fatalf("first page %s", r.Body)
	}
	r = e.get("/ns/m/rev/" + head + "/heads?after=b")
	m = r.Obj()
	if hs, _ := m["heads"].([]any); len(hs) != 1 || hs[0].(map[string]any)["resource"] != "c" {
		t.Fatalf("last page %s", r.Body)
	}
	if _, has := m["next"]; has {
		t.Fatalf("last page %s names a next", r.Body)
	}
	// An empty page is still { heads: [] }.
	r = e.get("/ns/m/rev/" + head + "/heads?after=z")
	if hs, ok := r.Obj()["heads"].([]any); !ok || len(hs) != 0 {
		t.Fatalf("empty page %s", r.Body)
	}
}

// §7.1, §7.4, §E.2.2 (RH-12, ENC-6): a sealed 200 of /rev/{id} and of
// /ns/{ns}/rev/{ns_id} has ETag "{id}.{e}", e the stored sealing's epoch,
// which If-None-Match is compared with; "{id}" alone, perhaps served in
// plaintext before the namespace was sealed, doesn't match. Writes take
// the id without .{e}.
func TestV073SealedETagNamesEpoch(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	a1 := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	ns1 := e.nsHead("s")
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0)), ""), 201)
	a2 := e.wr("s", "a", a1, withNonce(ops(op("replace", "/v", 2.0)))) // If-Match "{a1}"
	ns2 := e.nsHead("s")
	for _, c := range []struct{ path, id, e string }{
		{"/r/s/a/rev/" + a1, a1, "1"},
		{"/r/s/a/rev/" + a2, a2, "2"},
		{"/ns/s/rev/" + ns1, ns1, "1"},
		{"/ns/s/rev/" + ns2, ns2, "2"},
	} {
		r := e.get(c.path)
		expect(t, r, 200)
		tag := quote(c.id + "." + c.e)
		if !isJOSE(r) || r.H.Get("ETag") != tag {
			t.Errorf("%s: ETag %q, want %s", c.path, r.H.Get("ETag"), tag)
		}
		for inm, want := range map[string]int{tag: 304, "W/" + tag: 304, `"x", ` + tag: 304, quote(c.id): 200, quote(c.id + ".9"): 200} {
			if got := e.do(req{method: "GET", path: c.path, hdr: map[string]string{"If-None-Match": inm}}); got.Code != want {
				t.Errorf("%s If-None-Match %s: %d, want %d", c.path, inm, got.Code, want)
			}
		}
	}
	// Head pointers keep "{id}".
	if h := e.get("/r/s/a"); h.H.Get("ETag") != quote(a2) {
		t.Errorf("head pointer ETag %q", h.H.Get("ETag"))
	}
	if h := e.get("/ns/s"); h.H.Get("ETag") != quote(ns2) {
		t.Errorf("namespace head pointer ETag %q", h.H.Get("ETag"))
	}
	// A namespace that isn't sealed keeps "{id}".
	e.mkNS("p", map[string]any{"read": "public"})
	p1 := e.create("p", "a", map[string]any{})
	if r := e.get("/r/p/a/rev/" + p1); r.H.Get("ETag") != quote(p1) {
		t.Errorf("plain ETag %q", r.H.Get("ETag"))
	}
}

// §7.4, §8.5 (RH-19, BBD-10): once the namespace is purged, /branches is
// 410 purged with head, after the unrestricted-read check, in the long
// class with the namespace's tag.
func TestV073BranchesOfPurgedNamespace(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	expect(t, e.patchNS("sec", ops(op("add", "/frozen", true)), f.adminG), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/sec/purge", ifMatch: e.nsHead("sec", f.adminG), bearer: f.adminG}), 204)
	head := e.nsHead("sec", f.adminG)
	r := e.get("/ns/sec/branches", f.adminG)
	expectCode(t, r, 410, "purged")
	if r.Str("head") != head {
		t.Errorf("head %q, want the purge-ns entry %s", r.Str("head"), head)
	}
	if cc := r.H.Get("Cache-Control"); cc != "private, max-age=0" && cc != ccLong {
		t.Errorf("Cache-Control %q", cc)
	}
	if r.H.Get("Cache-Tag") != "ns:sec" {
		t.Errorf("Cache-Tag %q", r.H.Get("Cache-Tag"))
	}
	// Without unrestricted read, the read check answers first, as for a
	// namespace that isn't purged.
	limited := e.grant(f.issuer, "user:l", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	if r := e.get("/ns/sec/branches", limited); r.Code != 404 {
		t.Errorf("limited reader: %d %s, want the read check's 404", r.Code, r.Body)
	}
	// A public namespace's 410 is cached long.
	p := newEnv(t)
	p.mkNS("pub", map[string]any{"read": "public"})
	expect(t, p.patchNS("pub", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, p.do(req{method: "POST", path: "/ns/pub/purge", ifMatch: p.nsHead("pub"), author: "admin"}), 204)
	r = p.get("/ns/pub/branches")
	expectCode(t, r, 410, "purged")
	if r.H.Get("Cache-Control") != ccLong || r.H.Get("Cache-Tag") != "ns:pub" {
		t.Errorf("public 410: %v", r.H)
	}
}

// §9 (RH-45): Short answers (unknown-id 404) and Long answers (410 of a
// purged resource or namespace) carry ns:{ns}, and r:{ns}/{name} on
// resource URLs, so a purge of either tag clears them.
func TestV073ShortAndLongAnswersTagged(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	a := e.create("m", "a", map[string]any{})
	bid := e.upload("m", "a", "text/plain", []byte("hi"))
	unknown := hashID(t, "", []byte("nothing"))
	res := "ns:m,r:m/a"
	check := func(path string, code int, class, tags string) {
		t.Helper()
		r := e.get(path)
		if r.Code != code || r.H.Get("Cache-Control") != class || r.H.Get("Cache-Tag") != tags {
			t.Errorf("%s: %d %q %q, want %d %q %q", path, r.Code, r.H.Get("Cache-Control"), r.H.Get("Cache-Tag"), code, class, tags)
		}
	}
	check("/r/m/nope", 404, ccShort, "ns:m,r:m/nope")
	check("/r/m/a/rev/"+unknown, 404, ccShort, res)
	check("/r/m/a/rev/"+unknown+"/log", 404, ccShort, res)
	check("/r/m/a/rev/"+unknown+"/raw", 404, ccShort, res)
	check("/r/m/a/blob/"+unknown, 404, ccShort, res)
	check("/r/m/a/log", 302, ccHead, res)
	check("/r/m/nope/log", 404, ccShort, "ns:m,r:m/nope")
	check("/ns/m/rev/"+unknown, 404, ccShort, "ns:m")
	check("/ns/m/rev/"+unknown+"/log", 404, ccShort, "ns:m")
	check("/ns/m/rev/"+unknown+"/heads", 404, ccShort, "ns:m")
	check("/ns/m/grants/"+unknown, 404, ccShort, "ns:m")
	expect(t, e.purge("m", "a", a, "admin"), 204)
	check("/r/m/a", 410, ccLong, res)
	check("/r/m/a/rev/"+a, 410, ccLong, res)
	check("/r/m/a/rev/"+a+"/log", 410, ccLong, res)
	check("/r/m/a/blob/"+bid, 410, ccLong, res)
	check("/r/m/a/log", 410, ccLong, res)
	// A purged namespace's URLs (§8.5).
	expect(t, e.patchNS("m", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/m/purge", ifMatch: e.nsHead("m"), author: "admin"}), 204)
	head := e.nsHead("m")
	check("/r/m/b", 410, ccLong, "ns:m,r:m/b")
	check("/ns/m/rev/"+head+"/heads", 410, ccLong, "ns:m")
	check("/ns/m/branches", 410, ccLong, "ns:m")
}

// thumbprintOf is the RFC 7638 thumbprint of an Ed25519 key entry's pub,
// computed by hand: sha-256 of {"crv":"Ed25519","kty":"OKP","x":…}.
func thumbprintOf(t *testing.T, pub string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(pub)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("pub %q: %v", pub, err)
	}
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(raw) + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// §7.4, §C.4, §H.7 (RH-22, RH-23, GR-41): /principal gives key, the RFC
// 7638 thumbprint of the verifying key, the same under different kids in
// different namespaces, and operator, true only for an operator grant
// (can its blocks' verbs, roles []); with authentication disabled there
// is no key and operator is false.
func TestV073PrincipalKeyAndOperator(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	// The issuer's key, under another kid, in a second namespace.
	other := keyPair{kid: "elsewhere", pub: f.issuer.pub, priv: f.issuer.priv}
	expect(t, e.do(req{method: "PATCH", path: "/ns/two", ifNoneMatch: "*", bearer: e.operatorGrant("two"),
		body: addRoot(map[string]any{"read": "grant", "keys": []any{other.entry("read")}})}), 201)
	want := thumbprintOf(t, f.issuer.pub)
	r := e.principalOf("sec", f.issuerG)
	expect(t, r, 200)
	b := r.Obj()
	if b["key"] != want || b["kid"] != "issuer" || b["operator"] != false {
		t.Fatalf("namespace grant: key %v kid %v operator %v, want %s issuer false", b["key"], b["kid"], b["operator"], want)
	}
	r = e.principalOf("two", e.grant(other, "user:bob", []string{"two"}, []string{"read"}))
	expect(t, r, 200)
	if b := r.Obj(); b["key"] != want || b["kid"] != "elsewhere" {
		t.Fatalf("same key under kid elsewhere: key %v kid %v, want %s", b["key"], b["kid"], want)
	}
	// An operator grant: its published JWK's thumbprint.
	r = e.principalOf("sec", e.operatorGrant("sec"))
	expect(t, r, 200)
	b = r.Obj()
	opPub := base64.RawURLEncoding.EncodeToString(e.opPriv.Public().(ed25519.PublicKey))
	if b["operator"] != true || b["key"] != thumbprintOf(t, opPub) || len(strsOf(b["roles"])) != 0 ||
		!slices.Equal(strsOf(b["can"]), []string{"config"}) {
		t.Fatalf("operator grant %s", r.Body)
	}
	set := e.get("/.well-known/patchlog-keys").Obj()["keys"].([]any)[0].(map[string]any)
	if set["x"] != opPub {
		t.Fatalf("published operator JWK %v", set)
	}
	// Authentication disabled.
	d := newEnv(t)
	d.mkNS("d", map[string]any{})
	r = d.principalOf("d", "")
	expect(t, r, 200)
	b = r.Obj()
	if _, has := b["key"]; has || b["operator"] != false {
		t.Fatalf("auth disabled: %s", r.Body)
	}
}

// §7.4, §B.6, §H.2 (RH-24): a catalog namespace's /principal gives
// catalog: trust ([] when absent) and files to a grant with unrestricted
// read; to any other, files without x- members and trusted in place of
// trust. Other namespaces have no catalog member.
func TestV073PrincipalCatalog(t *testing.T) {
	t.Parallel()
	files := map[string]any{"ns": "docs", "root": "root", "x-note": "internal"}
	f := newAuthFixture(t, map[string]any{"catalog": map[string]any{"trust": []any{"docs", "media"}, "mode": "tree", "files": files}})
	e := f.tenv
	r := e.principalOf("sec", f.issuerG)
	expect(t, r, 200)
	c, _ := r.Obj()["catalog"].(map[string]any)
	if !slices.Equal(strsOf(c["trust"]), []string{"docs", "media"}) || c["files"].(map[string]any)["x-note"] != "internal" {
		t.Fatalf("unrestricted reader's catalog %v", c)
	}
	if _, has := c["trusted"]; has {
		t.Fatalf("unrestricted reader gets trusted: %v", c)
	}
	// A grant limited to some resources, and one without read.
	for name, g := range map[string]string{
		"limited": e.grant(f.issuer, "user:l", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}}),
		"no read": e.grant(f.issuer, "user:w", []string{"sec"}, []string{"append"}),
	} {
		r := e.principalOf("sec", g)
		expect(t, r, 200)
		c, _ := r.Obj()["catalog"].(map[string]any)
		fl, _ := c["files"].(map[string]any)
		if _, has := c["trust"]; has || c["trusted"] != true || fl["ns"] != "docs" || fl["root"] != "root" {
			t.Errorf("%s: catalog %v", name, c)
		}
		if _, has := fl["x-note"]; has {
			t.Errorf("%s: files keeps its x- member: %v", name, fl)
		}
	}
	// files.ns not trusted, and a catalog without trust or files.
	expect(t, e.patchNS("sec", ops(op("replace", "/catalog/files/ns", "elsewhere")), f.adminG), 201)
	r = e.principalOf("sec", e.grant(f.issuer, "user:w", []string{"sec"}, []string{"append"}))
	if c, _ := r.Obj()["catalog"].(map[string]any); c["trusted"] != false {
		t.Errorf("untrusted files.ns: %v", c)
	}
	expect(t, e.patchNS("sec", ops(op("replace", "/catalog", map[string]any{"mode": "dag"})), f.adminG), 201)
	r = e.principalOf("sec", f.issuerG)
	if c, _ := r.Obj()["catalog"].(map[string]any); c == nil || c["trust"] == nil || len(strsOf(c["trust"])) != 0 {
		t.Errorf("catalog without trust: %s", r.Body)
	}
	if _, has := r.Obj()["catalog"].(map[string]any)["files"]; has {
		t.Errorf("catalog without files has files: %s", r.Body)
	}
	r = e.principalOf("sec", e.grant(f.issuer, "user:w", []string{"sec"}, []string{"append"}))
	if c, _ := r.Obj()["catalog"].(map[string]any); c["trusted"] != false {
		t.Errorf("catalog without files, limited: %v", c)
	}
	// Not a catalog.
	expect(t, e.patchNS("sec", ops(op("remove", "/catalog")), f.adminG), 201)
	if _, has := e.principalOf("sec", f.issuerG).Obj()["catalog"]; has {
		t.Error("a namespace without catalog has a catalog member")
	}
}

// §7.8 Reading (BBD-20, BBD-21): a text/* blob's 200 is its type with
// "; charset=utf-8"; an application/pdf 200 or 206 is an attachment,
// sandboxed, unless the deployment opts into inline display, which drops
// the sandbox and keeps nosniff. Other types are served as stored.
func TestV073BlobTypeHeaders(t *testing.T) {
	t.Parallel()
	pdf := []byte("%PDF-1.7\n" + strings.Repeat("0", 64))
	for _, inline := range []bool{false, true} {
		var sopts []Option
		if inline {
			sopts = append(sopts, WithInlinePDF())
		}
		e := newEnvWith(t, sopts)
		e.mkNS("m", map[string]any{"read": "public"})
		blobs := map[string]string{}
		doc := map[string]any{}
		for typ, data := range map[string][]byte{"text/plain": []byte("hej"), "text/markdown": []byte("# hej"), "application/pdf": pdf, "image/png": []byte("\x89PNG")} {
			bid := e.upload("m", "a", typ, data)
			blobs[typ] = bid
			doc[strings.ReplaceAll(typ, "/", "-")] = ref(bid, typ, len(data), "")
		}
		e.create("m", "a", doc)
		for typ, want := range map[string]string{"text/plain": "text/plain; charset=utf-8", "text/markdown": "text/markdown; charset=utf-8", "image/png": "image/png", "application/pdf": "application/pdf"} {
			r := e.get(blobPath("m", "a", blobs[typ]))
			expect(t, r, 200)
			if r.H.Get("Content-Type") != want || r.H.Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("inline %v %s: Content-Type %q nosniff %q", inline, typ, r.H.Get("Content-Type"), r.H.Get("X-Content-Type-Options"))
			}
			if typ != "application/pdf" && (r.H.Get("Content-Security-Policy") != "sandbox" || r.H.Get("Content-Disposition") != "") {
				t.Errorf("%s: %v", typ, r.H)
			}
		}
		for _, rng := range []string{"", "bytes=0-3"} {
			q := req{method: "GET", path: blobPath("m", "a", blobs["application/pdf"])}
			want := 200
			if rng != "" {
				q.hdr, want = map[string]string{"Range": rng}, 206
			}
			r := e.do(q)
			expect(t, r, want)
			csp, cd := r.H.Get("Content-Security-Policy"), r.H.Get("Content-Disposition")
			switch {
			case !inline && (csp != "sandbox" || cd != "attachment"):
				t.Errorf("PDF %d: CSP %q Content-Disposition %q, want sandbox and attachment", want, csp, cd)
			case inline && (csp != "" || cd != ""):
				t.Errorf("inline PDF %d: CSP %q Content-Disposition %q, want neither", want, csp, cd)
			}
			if r.H.Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("PDF %d without nosniff", want)
			}
		}
		// Errors keep the sandbox, PDFs' included.
		if r := e.get(blobPath("m", "a", hashID(t, "", []byte("x")))); r.H.Get("Content-Security-Policy") != "sandbox" {
			t.Errorf("404: %v", r.H)
		}
	}
}

// §7.1, §8.3 (BBD-43): a purged resource's …/raw in a sealed namespace is
// the document URL's 410, before not_offered; a live one's stays 404
// not_offered.
func TestV073RawOfPurgedSealedResource(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	p1 := e.wr("s", "p", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	e.wr("s", "q", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	expect(t, e.purge("s", "p", p1, "admin"), 204)
	for _, path := range []string{"/r/s/p/raw", "/r/s/p/rev/" + p1 + "/raw"} {
		r := e.get(path)
		if r.Code != 410 || r.Str("code") == "not_offered" || r.H.Get("Cache-Control") != ccLong {
			t.Errorf("%s: %d %s %v, want the purge's 410, long", path, r.Code, r.Body, r.H.Get("Cache-Control"))
		}
	}
	expectCode(t, e.get("/r/s/q/raw"), 404, "not_offered")
}

// checkStored checks a /grants/{gid} answer's stored (§C.3.1): one
// base64url string, the authority SignedBlock of the token, which verifies
// under the root key, whose grant_block is the root block, whose id is
// gid, and which holds no narrowing block.
func checkStored(t *testing.T, m map[string]any, gid string, pub ed25519.PublicKey) {
	t.Helper()
	s, ok := m["stored"].(string)
	if !ok {
		t.Fatalf("stored %v: not one string", m["stored"])
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	g, err := grant.ParseStoredBlock(raw)
	if err != nil || len(g.Blocks) != 1 || g.ID().String() != gid || !g.SignedBy(pub) {
		t.Fatalf("stored block: %v", err)
	}
	if string(jsonv.Canonical(g.Blocks[0].Raw)) != string(jsonv.Canonical(m["root"])) {
		t.Fatalf("grant_block %v, root %v", g.Blocks[0].Raw, m["root"])
	}
	if strings.Contains(string(raw), "svc:a") {
		t.Fatal("stored holds a narrowing block")
	}
}

// §C.3.1, §E.2.2 (GR-30): /ns/{ns}/grants/{gid} serves stored as one
// string, the authority block, for a narrowed token too, in the clear and
// sealed.
func TestV073GrantStoredOneString(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	dg := delegated(t, e, f.issuer, "user:bob", []string{"sec"}, []string{"read", "create"})
	e.create("sec", "a", map[string]any{}, dg)
	gid := grantIDOf(t, dg)
	r := e.get("/ns/sec/grants/"+gid, f.adminG)
	expect(t, r, 200)
	checkStored(t, r.Obj(), gid, f.issuer.priv.Public().(ed25519.PublicKey))

	s := newSealedAuthEnv(t)
	k := newKey("issuer")
	expect(t, s.do(req{method: "PATCH", path: "/ns/s", ifNoneMatch: "*", bearer: s.operatorGrant("s"),
		body: addRoot(sealedDoc(map[string]any{"read": "public", "keys": []any{k.entry("read", "create")}}))}), 201)
	sg := delegated(t, s, k, "user:bob", []string{"s"}, []string{"read", "create"})
	s.wr("s", "x", "", withNonce(addRoot(map[string]any{})), sg)
	sgid := grantIDOf(t, sg)
	keys, kr := s.keysOf("s", nil, sg)
	expect(t, kr, 200)
	r = s.get("/ns/s/grants/"+sgid, sg)
	expect(t, r, 200)
	pt := open(t, string(r.Body), keys["s#1"], "s#1", seal.GrantPL("s", sgid))
	checkStored(t, jsonv.MustParse(pt).(map[string]any), sgid, k.priv.Public().(ed25519.PublicKey))
}

// §C.3.1, §E.2.2 (GR-30): a grant answer sealed before v0.73, with stored
// an array of every SignedBlock, is no longer served: the answer in
// today's shape is sealed in the same epoch, stored, and served from then
// on, the same bytes on every read.
func TestV073LegacySealedGrantConverted(t *testing.T) {
	t.Parallel()
	path, driver := filepath.Join(t.TempDir(), "legacy.db"), "sqlite"
	if pgtest.Enabled() {
		path, driver = pgtest.NewDB(t), "pgx"
	}
	s := newSealedAuthEnv(t, withPath(path))
	k := newKey("issuer")
	expect(t, s.do(req{method: "PATCH", path: "/ns/s", ifNoneMatch: "*", bearer: s.operatorGrant("s"),
		body: addRoot(sealedDoc(map[string]any{"read": "public", "keys": []any{k.entry("read", "create")}}))}), 201)
	sg := delegated(t, s, k, "user:bob", []string{"s"}, []string{"read", "create"})
	s.wr("s", "x", "", withNonce(addRoot(map[string]any{})), sg)
	sgid := grantIDOf(t, sg)
	keys, kr := s.keysOf("s", nil, sg)
	expect(t, kr, 200)
	// What a server before v0.73 stored: every SignedBlock, sealed under
	// the epoch of the first entry recording the grant.
	dec, err := grant.Decode(sg, 0)
	if err != nil {
		t.Fatal(err)
	}
	var blocks []any
	for _, b := range dec.SignedBlocks() {
		blocks = append(blocks, base64.RawURLEncoding.EncodeToString(b))
	}
	legacy, err := seal.SealUncompressed(keys["s#1"], "s#1", seal.GrantPL("s", sgid),
		jsonv.Canonical(map[string]any{"id": sgid, "root": dec.Blocks[0].Raw, "stored": blocks}))
	if err != nil {
		t.Fatal(err)
	}
	dsn := pgtest.DSN(path)
	if driver == "sqlite" {
		dsn = sqlitedsn.DSN(path, "_pragma=busy_timeout(10000)")
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	ph := func(i int) string {
		if driver == "pgx" {
			return "$" + strconv.Itoa(i)
		}
		return "?"
	}
	if _, err := db.Exec(`INSERT INTO sealed (ns, kind, key, jwe, created) SELECT ns, 'grant', `+ph(1)+`, `+ph(2)+`, 0 FROM namespaces WHERE name = 's'`, sgid, legacy); err != nil {
		t.Fatal(err)
	}
	db.Close()
	r := s.get("/ns/s/grants/"+sgid, sg)
	expect(t, r, 200)
	if string(r.Body) == legacy {
		t.Fatal("the legacy sealed answer is served")
	}
	pt := open(t, string(r.Body), keys["s#1"], "s#1", seal.GrantPL("s", sgid))
	checkStored(t, jsonv.MustParse(pt).(map[string]any), sgid, k.priv.Public().(ed25519.PublicKey))
	if again := s.get("/ns/s/grants/"+sgid, sg); string(again.Body) != string(r.Body) {
		t.Fatal("the converted answer's bytes differ between reads")
	}
}

// §8.3 Branches, invariant 7 (BBD-16): a branch created later, at an at
// before a purge, sees the name as purged only where it would read an
// entry for it through: there it answers 410, and /heads lists it as
// purge with its head as of at as target; a name without an entry as of
// at is 404 and not listed.
func TestV073LateBranchSeesPurgeAsOfAt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("main", map[string]any{"read": "public"})
	e.create("main", "a", map[string]any{})
	at0 := e.nsHead("main")
	x1 := e.create("main", "x", map[string]any{"v": 1.0})
	at1 := e.nsHead("main")
	x2 := e.appendRev("main", "x", x1, ops(op("replace", "/v", 2.0)))
	y1 := e.create("main", "y", map[string]any{})
	expect(t, e.purge("main", "x", x2, "admin"), 204)
	expect(t, e.purge("main", "y", y1, "admin"), 204)
	expect(t, e.branch("main", map[string]any{"name": "early", "at": at0}, "alice"), 201)
	expect(t, e.branch("main", map[string]any{"name": "late", "at": at1}, "alice"), 201)

	expect(t, e.get("/r/late/x"), 410)
	expect(t, e.get("/r/late/x/rev/"+x1), 410)
	expect(t, e.get("/r/late/y"), 404)
	expect(t, e.get("/r/early/x"), 404)
	expect(t, e.get("/r/early/y"), 404)
	heads := func(ns string) map[string]map[string]any {
		out := map[string]map[string]any{}
		for _, h := range e.get("/ns/" + ns + "/rev/" + e.nsHead(ns) + "/heads").Obj()["heads"].([]any) {
			m := h.(map[string]any)
			out[m["resource"].(string)] = m
		}
		return out
	}
	lh := heads("late")
	if x := lh["x"]; x == nil || x["kind"] != "purge" || x["target"] != x1 {
		t.Errorf("late /heads x %v, want purge with target %s, the head as of at", x, x1)
	}
	if _, listed := lh["y"]; listed {
		t.Errorf("late /heads lists y, which had no entry as of at: %v", lh["y"])
	}
	eh := heads("early")
	if _, listed := eh["x"]; listed || eh["a"] == nil {
		t.Errorf("early /heads %v: x listed or a missing", eh)
	}
	// The base itself still lists both as purged, with their heads then.
	mh := heads("main")
	if mh["x"]["kind"] != "purge" || mh["x"]["target"] != x2 || mh["y"]["kind"] != "purge" {
		t.Errorf("main /heads %v", mh)
	}
	// A late branch may create a name it never saw.
	expect(t, e.write("PATCH", "early", "x", "", addRoot(map[string]any{"new": true})), 201)
}

// headsAt reads ns's /heads at nsID, by resource.
func headsAt(t *testing.T, e *tenv, ns, nsID string) map[string]map[string]any {
	t.Helper()
	r := e.get("/ns/" + ns + "/rev/" + nsID + "/heads")
	expect(t, r, 200)
	out := map[string]map[string]any{}
	for _, h := range r.Obj()["heads"].([]any) {
		m := h.(map[string]any)
		out[m["resource"].(string)] = m
	}
	return out
}

// §8.3, invariant 7 (BBD-16): a branch that purges a name it reads
// through, or whose own chain began reading it through, keeps it purged
// at every ns_id at which it read an entry for it: its /heads lists it as
// purge with the head it read through then, and a branch of it, created
// before or after the purge, at any at, answers 410 for it, never the
// base's live content, which the purge leaves alone (purges never
// propagate upwards).
func TestV073BranchPurgeOfReadThroughStaysPurged(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("main", map[string]any{"read": "public"})
	x1 := e.create("main", "x", map[string]any{"secret": "s3cr3t"})
	z1 := e.create("main", "z", map[string]any{"v": 1.0})
	expect(t, e.branch("main", map[string]any{"name": "c"}, "alice"), 201)
	c0 := e.nsHead("c") // c reads x and z through
	expect(t, e.branch("c", map[string]any{"name": "b"}, "alice"), 201)
	z2 := e.appendRev("c", "z", z1, ops(op("replace", "/v", 2.0)))
	expect(t, e.get("/r/c/x"), 302)
	expect(t, e.purge("c", "x", x1, "admin"), 204)
	expect(t, e.purge("c", "z", z2, "admin"), 204)
	expect(t, e.get("/r/c/x"), 410)
	expect(t, e.get("/r/main/x"), 302)
	expect(t, e.get("/r/main/x/rev/"+x1), 200)

	want := func(ns string, h map[string]map[string]any, name, target string) {
		t.Helper()
		if x := h[name]; x == nil || x["kind"] != "purge" || x["target"] != target {
			t.Errorf("%s /heads %s: %v, want purge with target %s", ns, name, x, target)
		}
	}
	ch := headsAt(t, e, "c", e.nsHead("c"))
	want("c", ch, "x", x1)
	want("c", ch, "z", z2)
	// As of c0 c read both through: purged since, so purged then, with
	// the heads it read through.
	ch = headsAt(t, e, "c", c0)
	want("c@at", ch, "x", x1)
	want("c@at", ch, "z", z1)
	// b, a branch of c from before the purge, was purged by propagation.
	expect(t, e.get("/r/b/x"), 410)
	want("b", headsAt(t, e, "b", e.nsHead("b")), "x", x1)

	// Branches of c created after the purge, at its head and at c0.
	expect(t, e.branch("c", map[string]any{"name": "d"}, "alice"), 201)
	expect(t, e.branch("c", map[string]any{"name": "d0", "at": c0}, "alice"), 201)
	for _, ns := range []string{"d", "d0"} {
		for _, path := range []string{"/r/" + ns + "/x", "/r/" + ns + "/x/rev/" + x1, "/r/" + ns + "/z", "/r/" + ns + "/z/rev/" + z1} {
			if r := e.get(path); r.Code != 410 {
				t.Errorf("%s: %d %s, want 410: content c purged reappears in a later branch of c", path, r.Code, r.Body)
			}
		}
	}
	dh := headsAt(t, e, "d", e.nsHead("d"))
	want("d", dh, "x", x1)
	want("d", dh, "z", z2)
	d0h := headsAt(t, e, "d0", e.nsHead("d0"))
	want("d0", d0h, "x", x1)
	want("d0", d0h, "z", z1)
}

// §7.8 Reading (BBD-20): with WithInlinePDF only a 200 or 206 of an
// application/pdf blob goes without Content-Security-Policy: sandbox; its
// 304 and 416 keep it, as every other answer to a blob URL does.
func TestV073InlinePDFSandboxOnlyOff200And206(t *testing.T) {
	t.Parallel()
	e := newEnvWith(t, []Option{WithInlinePDF()})
	e.mkNS("m", map[string]any{"read": "public"})
	pdf := []byte("%PDF-1.7\n" + strings.Repeat("0", 64))
	bid := e.upload("m", "a", "application/pdf", pdf)
	e.create("m", "a", map[string]any{"f": ref(bid, "application/pdf", len(pdf), "")})
	for _, c := range []struct {
		hdr  map[string]string
		code int
		csp  string
	}{
		{nil, 200, ""},
		{map[string]string{"Range": "bytes=0-3"}, 206, ""},
		{map[string]string{"Range": "bytes=9999-"}, 416, "sandbox"},
		{map[string]string{"If-None-Match": `"` + bid + `"`}, 304, "sandbox"},
	} {
		r := e.do(req{method: "GET", path: blobPath("m", "a", bid), hdr: c.hdr})
		expect(t, r, c.code)
		if got := r.H.Get("Content-Security-Policy"); got != c.csp {
			t.Errorf("inline PDF %d: Content-Security-Policy %q, want %q", c.code, got, c.csp)
		}
		if r.H.Get("Content-Disposition") != "" || r.H.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("inline PDF %d: %v", c.code, r.H)
		}
	}
}

// §7.4, §C.4 (RH-24): an operator grant reads nothing that needs a grant
// (any such read under one is 401, whatever its blocks allow), so outside
// a public namespace /principal gives it the restricted catalog member:
// files without x- members, and trusted in place of trust. A public
// namespace's catalog is everyone's to read, so there it gets all of it.
func TestV073OperatorGrantRestrictedCatalog(t *testing.T) {
	t.Parallel()
	files := map[string]any{"ns": "docs", "root": "root", "x-note": "internal"}
	for _, read := range []string{"grant", "public"} {
		f := newAuthFixture(t, map[string]any{"read": read, "catalog": map[string]any{"trust": []any{"docs", "media"}, "mode": "tree", "files": files}})
		e := f.tenv
		op := mint(t, e.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"sec"}, "can": []any{"read", "config"},
			"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)})
		if read == "grant" {
			expect(t, e.get("/r/sec/anything", op), 401) // it can't read
		}
		r := e.principalOf("sec", op)
		expect(t, r, 200)
		if r.Obj()["operator"] != true {
			t.Fatalf("not an operator grant: %s", r.Body)
		}
		c, _ := r.Obj()["catalog"].(map[string]any)
		fl, _ := c["files"].(map[string]any)
		_, trust := c["trust"]
		_, note := fl["x-note"]
		switch {
		case read == "grant" && (trust || note || c["trusted"] != true || fl["ns"] != "docs"):
			t.Errorf("operator grant, which can't read sec: catalog %v, want files without x- members and trusted", c)
		case read == "public" && (!trust || !note || c["trusted"] != nil):
			t.Errorf("operator grant in a public namespace: catalog %v, want trust and files whole", c)
		}
	}
}
