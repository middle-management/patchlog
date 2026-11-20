package server

import (
	"strings"
	"testing"
	"time"
)

// V82-02 (v0.82): access at the origin. /now over the whole envelope, as the read check's ordinary
// answer and ignored where reads are public (ACC-1, ACC-2, ACC-4o);
// request-shape errors and other Authorization schemes (ACC-13); and a
// purged namespace's filtered /heads over HTTP (ACC-8b).

var (
	v82accessNow   = map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}
	v82accessWhole = map[string]any{"op": "test", "path": "", "schema": map[string]any{"required": []any{"action"}}}
)

// Grant scope 71 (§2.1 Refers to, §C.2 Unrestricted read, item 5): "a
// rule on the whole envelope refers to /now, so it fails every read and
// the unrestricted-read check". A grant with read whose only block rule
// tests "": the log is 403, a resource 404 and branching 403; the same
// rule as a key-scope rule and as the only read role's does the same,
// while the grant's writes still pass.
func TestV082AccessWholeEnvelopeRule(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k, scoped := newKey("k"), newKey("scoped")
	se := scoped.entry("read", "append", "branch")
	se["rules"] = []any{v82accessWhole}
	e.mkNS("n", map[string]any{"read": "grant", "keys": []any{k.entry("*"), se},
		"roles": map[string]any{"env": map[string]any{"can": []any{"read", "append", "branch"}, "rules": []any{v82accessWhole}}}})
	admin := e.grant(k, "user:root", []string{"n", "n-b"}, allVerbs)
	x := e.create("n", "x", map[string]any{"n": 0.0}, admin)
	verbs := []string{"read", "append", "branch"}
	for name, g := range map[string]string{
		"a block rule":     e.grant(k, "user:r", []string{"n", "n-b"}, verbs, map[string]any{"rules": []any{v82accessWhole}}),
		"a key-scope rule": e.grant(scoped, "user:r", []string{"n", "n-b"}, verbs),
		"a role's rule":    e.grant(k, "user:r", []string{"n", "n-b"}, verbs, map[string]any{"roles": []any{"env"}}),
	} {
		head := e.nsHead("n", admin)
		expect(t, e.get("/ns/n/log", g), 403)
		expect(t, e.get("/ns/n/rev/"+head+"/heads", g), 403)
		expect(t, e.get("/r/n/x", g), 404)
		expect(t, e.get("/ns/n/gestures/"+gA, g), 403)
		r := e.do(req{method: "POST", path: "/ns/n/branches", ifNoneMatch: "*", bearer: g, body: map[string]any{"name": "n-b", "at": head, "patches": []any{}}})
		if r.Code != 403 {
			t.Errorf("%s: branching %d %s, want 403", name, r.Code, r.Body)
		}
		// A write has a now and an action: the rule passes it.
		x = e.appendRev("n", "x", x, ops(op("replace", "/n", 1.0)), g)
	}
}

// Grant scope 72 (§7 step 1, §C.2 item 5, §7.4, §E.2.3), ACC-4o: where
// reads are public the grant is ignored: a grant with a block rule on
// /now, a malformed one, an oversized one, one for another namespace and
// another Authorization scheme each get the unauthenticated answer, never
// a grant's 401, 403 or 413. POST /keys never ignores the grant: 403 for
// the /now one in public sealed pubs, whose /principal, which evaluates no
// rule, is 200.
func TestV082AccessPublicIgnoresGrant(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t, withKeyStore(newKeyStore(t)), withEncTuning)
	k := newKey("k")
	e.mkNS("pub", map[string]any{"read": "public", "keys": []any{k.entry("*")}})
	e.mkNS("priv", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	admin := e.grant(k, "user:root", []string{"pub", "priv", "pubs"}, allVerbs)
	e.create("pub", "x", map[string]any{"n": 0.0}, admin)
	e.create("priv", "x", map[string]any{"n": 0.0}, admin)
	now := e.grant(k, "user:r", []string{"pub", "priv", "pubs"}, []string{"read"}, map[string]any{"rules": []any{v82accessNow}})
	big := "x" + strings.Repeat("A", 200_000)
	auths := map[string]string{
		"a grant with a block rule on /now": "Bearer " + now,
		"a malformed grant":                 "Bearer not-a-grant",
		"an oversized grant":                "Bearer " + big,
		"a grant for another namespace":     "Bearer " + e.grant(k, "user:r", []string{"priv"}, []string{"read"}),
		"another scheme":                    "Basic dXNlcjpwYXNz",
	}
	head := e.nsHead("pub")
	for _, path := range []string{"/r/pub/x", "/ns/pub", "/ns/pub/rev/" + head + "/heads", "/ns/pub/rev/" + head + "/log"} {
		anon := e.get(path)
		if anon.Code >= 400 {
			t.Fatalf("%s without credentials: %d %s", path, anon.Code, anon.Body)
		}
		for name, auth := range auths {
			r := e.do(req{method: "GET", path: path, hdr: map[string]string{"Authorization": auth}})
			if r.Code != anon.Code || r.String() != anon.String() || r.H.Get("Location") != anon.H.Get("Location") || r.H.Get("ETag") != anon.H.Get("ETag") {
				t.Errorf("%s with %s: %d %s, want the unauthenticated answer %d %s", path, name, r.Code, r.Body, anon.Code, anon.Body)
			}
		}
	}
	// The same credentials at a private namespace are a grant's refusals:
	// any Authorization field other than a usable Bearer grant is 401
	// (§C.8 Transport), the /now grant 404 at a resource URL.
	for name, want := range map[string]int{"a grant with a block rule on /now": 404, "a malformed grant": 401, "another scheme": 401} {
		if r := e.do(req{method: "GET", path: "/r/priv/x", hdr: map[string]string{"Authorization": auths[name]}}); r.Code != want {
			t.Errorf("/r/priv/x with %s: %d %s, want %d", name, r.Code, r.Body, want)
		}
	}
	if r := e.do(req{method: "GET", path: "/r/priv/x", hdr: map[string]string{"Authorization": auths["an oversized grant"]}}); r.Code != 413 && r.Code != 401 {
		t.Errorf("/r/priv/x with an oversized grant: %d %s, want 413 or 401", r.Code, r.Body)
	}
	expect(t, e.get("/ns/priv/log", now), 403)

	e.mkNS("pubs", sealedDoc(map[string]any{"read": "public", "keys": []any{k.entry("*")}}))
	expectCode(t, e.do(req{method: "POST", path: "/ns/pubs/keys", body: map[string]any{}, bearer: now}), 403, "forbidden")
	expect(t, e.get("/ns/pubs/principal", now), 200)
	if r := e.do(req{method: "POST", path: "/ns/pubs/keys", body: map[string]any{}, bearer: admin}); r.Code != 200 {
		t.Fatalf("/keys for an unrestricted reader of pubs: %d %s", r.Code, r.Body)
	}
}

// Grant scope 73 (§7.4, §C.2 items 2 and 5) and Encryption 76 (§2.1
// Unrestricted read, §E.2.3): a grant whose only role lists read and has
// a /now rule reads nothing: the gestures listing is 403, never 200 with
// nothing listed, and in a sealed namespace POST /keys is 403, never K_e.
// Beside a role that refers to /resource it still gets no K_e: neither
// role gives unrestricted read (ACC-3).
func TestV082AccessNowRoleReadsNothing(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t, withKeyStore(newKeyStore(t)), withEncTuning)
	k := newKey("k")
	prefixed := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^pub-"}}
	roles := map[string]any{
		"clock":    map[string]any{"can": []any{"read", "branch"}, "rules": []any{v82accessNow}},
		"prefixed": map[string]any{"can": []any{"read", "branch"}, "rules": []any{prefixed}},
		"reader":   map[string]any{"can": []any{"read", "branch"}},
	}
	e.mkNS("p", map[string]any{"read": "grant", "keys": []any{k.entry("*")}, "roles": roles})
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}, "roles": roles}))
	admin := e.grant(k, "user:root", []string{"p", "s"}, allVerbs)
	e.create("p", "pub-a", map[string]any{"n": 0.0}, admin)
	with := func(roles ...any) string {
		return e.grant(k, "user:r", []string{"p", "s", "p-b"}, []string{"read", "branch"}, map[string]any{"roles": roles})
	}
	keys := func(g string) int {
		return e.do(req{method: "POST", path: "/ns/s/keys", body: map[string]any{}, bearer: g}).Code
	}
	branch := func(g string) int {
		return e.do(req{method: "POST", path: "/ns/p/branches", ifNoneMatch: "*", bearer: g,
			body: map[string]any{"name": "p-b", "at": e.nsHead("p", admin), "patches": []any{}}}).Code
	}
	clock := with("clock")
	expectCode(t, e.get("/ns/p/gestures/"+gA, clock), 403, "forbidden")
	expect(t, e.get("/ns/p/log", clock), 403)
	expect(t, e.get("/r/p/pub-a", clock), 404)
	if c := keys(clock); c != 403 {
		t.Errorf("/keys with the /now role alone: %d, want 403", c)
	}
	if c := branch(clock); c != 403 {
		t.Errorf("branching with the /now role alone: %d, want 403", c)
	}
	// Beside a /resource role: read per resource, never unrestricted.
	both := with("clock", "prefixed")
	expect(t, e.get("/r/p/pub-a", both), 302)
	expect(t, e.get("/ns/p/log", both), 302) // a partial reader (§7.9)
	if c := keys(both); c != 403 {
		t.Errorf("/keys with a /now role and a /resource role: %d, want 403 (no K_e)", c)
	}
	if c := branch(both); c != 403 {
		t.Errorf("branching with a /now role and a /resource role: %d, want 403", c)
	}
	// Beside a role with neither rule, that one reads unrestricted.
	whole := with("clock", "reader")
	if r := e.get("/ns/p/gestures/"+gA, whole); r.Code == 403 {
		t.Errorf("the gestures listing beside reader: %d %s", r.Code, r.Body)
	}
	if c := keys(whole); c != 200 {
		t.Errorf("/keys beside reader: %d, want 200", c)
	}
	if c := branch(whole); c != 201 {
		t.Errorf("branching beside reader: %d, want 201", c)
	}
}

// §C.2 item 5, §8.5 (ACC-2): the /now refusal is the read check's own
// answer, so it comes before a purged namespace's 410: 404 at a resource's
// URLs and 403 elsewhere, POST /keys and the filtered URLs included, where
// a grant that passes the read check gets the 410. GET /ns/{ns}/principal
// evaluates no rule.
func TestV082AccessNowBeforePurged(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	li := w.li()
	now := w.li(map[string]any{"rules": []any{v82accessNow}})
	env := w.li(map[string]any{"rules": []any{v82accessWhole}})
	nowAdmin := w.grant(w.k, "user:root", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{v82accessNow}})
	gs, at := w.filtered(li)
	rev := etagOf(w.get("/r/matches/derby", w.admin))
	head := v82accessPurge(t, w)
	for _, c := range []struct {
		path  string
		grant int // the /now grants
		good  int // li, or the admin where li may not read
		admin bool
	}{
		{"/r/matches/derby", 404, 410, false},
		{"/r/matches/derby/rev/" + rev, 404, 410, false},
		{"/ns/matches/rev/" + head + "/heads", 403, 410, true},
		{"/ns/matches/gestures/" + gA, 403, 410, false},
		{"/ns/matches/view/" + gs + "/heads", 403, 410, false},
		{"/ns/matches/view/" + gs + "/at/" + at + "/heads", 403, 410, false},
	} {
		good := li
		if c.admin {
			good = w.admin
		}
		if r := w.get(c.path, good); r.Code != c.good {
			t.Errorf("%s for a reader: %d %s, want %d", c.path, r.Code, r.Body, c.good)
		}
		for name, g := range map[string]string{"a block rule on /now": now, "a block rule on the envelope": env, "an unrestricted reader's /now rule": nowAdmin} {
			r := w.get(c.path, g)
			if r.Code != c.grant || strings.Contains(r.String(), "purged") || strings.Contains(r.String(), head) {
				t.Errorf("%s with %s: %d %s, want %d before the 410", c.path, name, r.Code, r.Body, c.grant)
			}
		}
	}
	for name, g := range map[string]string{"a block rule on /now": now, "an unrestricted reader's /now rule": nowAdmin} {
		if r := w.do(req{method: "POST", path: "/ns/matches/keys", body: map[string]any{}, bearer: g}); r.Code != 403 {
			t.Errorf("POST /keys with %s: %d %s, want 403", name, r.Code, r.Body)
		}
		if r := w.get("/ns/matches/principal", g); r.Code == 403 || r.Code == 404 {
			t.Errorf("/principal with %s: %d %s: it evaluates no rule", name, r.Code, r.Body)
		}
	}
}

// v82accessPurge freezes and purges w's matches and returns its purge-ns
// id.
func v82accessPurge(t *testing.T, w *v75s) string {
	t.Helper()
	opg := mint(t, w.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"matches"}, "can": []any{"purge-ns"},
		"exp": w.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	expect(t, w.patchNS("matches", ops(op("add", "/frozen", true)), w.admin), 201)
	expect(t, w.do(req{method: "POST", path: "/ns/matches/purge?force=1", ifMatch: w.nsHead("matches", w.admin), bearer: opg}), 204)
	return w.nsHead("matches", w.admin)
}

// Conformance 124, second half, over HTTP (ACC-8b): covered matches is
// purged. li's grant at another subject set's /view/{gs}/heads is 403, not
// 410; at her own, 410. An unrestricted reader's grant is 403 at the
// filtered URLs, as at a live namespace's, and 410 at the unfiltered
// /heads. None of the 403s shows the purge.
func TestV082AccessPurgedFilteredHeads(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, []string{"secret"}, []string{"derby", "secret"})
	li, bo := w.li(), w.bo()
	liGS, at := w.filtered(li)
	boGS, _ := w.filtered(bo)
	if liGS == boGS {
		t.Fatal("li and bo share a gs")
	}
	head := v82accessPurge(t, w)
	for _, c := range []struct {
		who, bearer, gs string
		want            int
	}{
		{"li at her own gs", li, liGS, 410},
		{"li at another subject set's", li, boGS, 403},
		{"bo at li's", bo, liGS, 403},
		{"an unrestricted reader at li's gs", w.admin, liGS, 403},
		{"an unrestricted reader at bo's gs", w.admin, boGS, 403},
		{"no credentials", "", liGS, 401},
	} {
		for _, path := range []string{"/ns/matches/view/" + c.gs + "/heads", "/ns/matches/view/" + c.gs + "/at/" + at + "/heads"} {
			r := w.get(path, c.bearer)
			if r.Code != c.want {
				t.Errorf("%s, %s: %d %s, want %d", c.who, path, r.Code, r.Body, c.want)
			}
			if c.want == 410 {
				expectCode(t, r, 410, "purged")
			} else if strings.Contains(r.String(), "purged") || strings.Contains(r.String(), head) {
				t.Errorf("%s, %s: the refusal shows the purge: %s", c.who, path, r.Body)
			}
		}
	}
	expectCode(t, w.get("/ns/matches/rev/"+head+"/heads", w.admin), 410, "purged")
}

// Conformance 125 (§7.9 URLs, §6.2): /ns/matches/view/all/…, and a gs or
// at that isn't an id in text form, are 400 bad_input, a request-shape
// error, before any 401 or 403: without credentials, with a grant the
// read check refuses, with a partial reader's, and for a namespace that
// doesn't exist or isn't covered.
func TestV082AccessFilteredShapeFirst(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	li := w.li()
	gs, at := w.filtered(li)
	since := w.nsHead("matches", w.admin)
	refused := w.grant(w.k, "user:x", []string{"cat-season"}, []string{"read"})
	now := w.li(map[string]any{"rules": []any{v82accessNow}})
	paths := []string{
		"/ns/matches/view/all/heads",
		"/ns/matches/view/all/at/" + at + "/heads",
		"/ns/matches/view/all/at/" + at + "/log",
		"/ns/matches/view/all/log?live=long-poll&since=" + since,
		"/ns/matches/view/all/events",
		"/ns/matches/view/" + strings.ToUpper(gs) + "/heads",
		"/ns/matches/view/" + gs[:len(gs)-1] + "/heads",
		"/ns/matches/view/" + gs + "/at/all/heads",
		"/ns/matches/view/" + gs + "/at/" + at[:len(at)-1] + "/log",
		"/ns/matches/view/" + gs + "/at/" + at + "x/heads",
		"/ns/nowhere/view/all/heads",
		"/ns/cat-season/view/all/heads",
	}
	for _, path := range paths {
		for name, bearer := range map[string]string{"no credentials": "", "a malformed grant": "garbage", "a grant for another namespace": refused,
			"a grant with a /now rule": now, "li": li, "an unrestricted reader": w.admin} {
			r := w.get(path, bearer)
			if r.Code != 400 || r.Str("code") != "bad_input" {
				t.Errorf("%s with %s: %d %s, want 400 bad_input", path, name, r.Code, r.Body)
			}
		}
	}
	// Well-formed, the same requests get the read check's answers.
	expect(t, w.get("/ns/matches/view/"+gs+"/heads", ""), 401)
	expect(t, w.get("/ns/matches/view/"+gs+"/heads", now), 403)
	expect(t, w.get("/ns/matches/view/"+gs+"/heads", w.admin), 403)
	expect(t, w.get("/ns/matches/view/"+gs+"/heads", li), 302)
}
