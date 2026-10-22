package server

import (
	"slices"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
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
