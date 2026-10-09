package server

import (
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/edge"
)

// v0.47 §C.5 "Issuing them": a grant with roles needs one role that lists
// read and qualifies (no rule refers to /resource or /now, and it passes
// now); roles are alternatives, and the grant's own blocks apply on top,
// fixing /resource if they will. This is implementer report B8: a
// rule-free reader role next to writer roles testing /resource by pattern.
func TestV047EdgeGrantRoles(t *testing.T) {
	t.Parallel()
	resRule := func(v string) map[string]any { return map[string]any{"op": "test", "path": "/resource", "value": v} }
	f := newAuthFixture(t, map[string]any{"roles": map[string]any{
		"reader": map[string]any{"can": []any{"read"}},
		"writer": map[string]any{"can": []any{"read", "append"}, "rules": []any{
			map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": "^draft-"}}}},
		"fixer":   map[string]any{"can": []any{"read"}, "rules": []any{resRule("a")}},
		"clock":   map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}},
		"bobonly": map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/principal/id", "value": "user:bob"}}},
		"lister":  map[string]any{"can": []any{"append"}},
	}})
	e := f.tenv
	e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	e.create("sec", "b", map[string]any{"v": 2.0}, f.adminG)
	issue := func(sub string, roles []any, rules ...any) *resp {
		extra := map[string]any{"roles": roles}
		if len(rules) > 0 {
			extra["rules"] = rules
		}
		return e.do(req{method: "POST", path: "/edge-grants", bearer: e.grant(f.issuer, sub, []string{"sec"}, nil, extra)})
	}
	prefixes := func(r *resp) string {
		t.Helper()
		var ps []string
		for _, p := range r.Obj()["prefixes"].([]any) {
			ps = append(ps, p.(string))
		}
		return strings.Join(ps, " ")
	}

	// B8: the reader qualifies; the grant's rule fixes the prefix.
	r := issue("user:li", []any{"reader", "writer"}, resRule("a"))
	expect(t, r, 200)
	if got := prefixes(r); got != "/r/sec/a" {
		t.Fatalf("prefixes %s", got)
	}
	c := edgeCookies(t, r)["/r/sec/a"]
	expect(t, e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(c)}), 302)
	expect(t, e.do(req{method: "GET", path: "/r/sec/b", hdr: cookieHdr(c)}), 401)

	// Without the rule, the reader reads every resource: namespace-wide.
	for _, roles := range [][]any{{"reader", "writer"}, {"reader", "clock"}, {"bobonly", "fixer"}} {
		r := issue("user:bob", roles)
		expect(t, r, 200)
		if got := prefixes(r); got != "/r/sec /ns/sec" {
			t.Fatalf("%v: prefixes %s", roles, got)
		}
	}

	// No qualifying role: each tests /resource (even one fixing it, or
	// next to a block fixing it) or /now, fails now for the principal, or
	// doesn't list read.
	for name, r := range map[string]*resp{
		"pattern":         issue("user:li", []any{"writer"}, resRule("draft-1")),
		"role fixes":      issue("user:li", []any{"fixer"}),
		"role and block":  issue("user:li", []any{"fixer"}, resRule("a")),
		"now":             issue("user:li", []any{"clock", "writer"}),
		"principal":       issue("user:li", []any{"bobonly"}),
		"no read":         issue("user:li", []any{"lister", "fixer"}),
		"block refuses":   issue("user:li", []any{"reader"}, map[string]any{"op": "test", "path": "/principal/id", "value": "user:bob"}),
		"block unfixed":   issue("user:li", []any{"reader"}, map[string]any{"not": resRule("b")}),
		"blocks disagree": issue("user:li", []any{"reader"}, resRule("a"), resRule("b")),
	} {
		if r.Code != 403 || r.H.Get("Set-Cookie") != "" {
			t.Errorf("%s: %d %s %v", name, r.Code, r.Body, r.H.Values("Set-Cookie"))
		}
	}
}

// v0.47 §C.5: POST /edge-grants answers all or nothing. A namespace the
// grant names that doesn't exist or refuses it refuses the request, 401
// if any of them would be 401, rather than being skipped.
func TestV047EdgeGrantsAllOrNothing(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	e.mkNS("sec2", map[string]any{"read": "grant", "keys": []any{f.admin.entry("*"), f.issuer.entry("append")}})
	e.mkNS("sec3", map[string]any{"read": "grant", "keys": []any{f.admin.entry("*")}})
	issue := func(ns ...string) *resp {
		return e.do(req{method: "POST", path: "/edge-grants", bearer: e.grant(f.issuer, "user:bob", ns, []string{"read", "append"})})
	}
	for _, c := range []struct {
		ns     []string
		status int
	}{
		{[]string{"sec"}, 200},
		{[]string{"sec", "sec2"}, 403},         // sec2: no read there
		{[]string{"sec", "nope"}, 401},         // doesn't exist
		{[]string{"sec2", "nope"}, 401},        // 401 wins, in either order
		{[]string{"nope", "sec2"}, 401},        //
		{[]string{"sec2", "sec3", "sec"}, 401}, // sec3 doesn't list the key
		{[]string{"sec2", "sec"}, 403},
	} {
		r := issue(c.ns...)
		if r.Code != c.status {
			t.Errorf("%v: %d %s", c.ns, r.Code, r.Body)
		}
		if c.status != 200 && len(r.H.Values("Set-Cookie")) > 0 {
			t.Errorf("%v: cookies set on a refusal: %v", c.ns, r.H.Values("Set-Cookie"))
		}
	}
	// A namespace that doesn't list the key and one that doesn't exist
	// answer alike, so the 401 doesn't reveal which exist (§C.4, §C.5).
	if a, b := issue("sec3"), issue("nope"); a.Code != 401 || string(a.Body) != string(b.Body) {
		t.Errorf("unlisted key %d %s, missing namespace %d %s", a.Code, a.Body, b.Code, b.Body)
	}
	if a, b := e.do(req{method: "GET", path: "/ns/sec3", bearer: e.grant(f.issuer, "user:bob", []string{"sec3"}, []string{"read"})}),
		e.do(req{method: "GET", path: "/ns/nope", bearer: e.grant(f.issuer, "user:bob", []string{"nope"}, []string{"read"})}); a.Code != 401 || string(a.Body) != string(b.Body) {
		t.Errorf("GET: unlisted key %d %s, missing namespace %d %s", a.Code, a.Body, b.Code, b.Body)
	}
}

// v0.47 §C.5: cookie attributes. Path is the prefix without its trailing
// /…, which covers the namespace URL itself and everything below it;
// SameSite is None when the deployment names credentialed origins.
func TestV047EdgeGrantCookies(t *testing.T) {
	t.Parallel()
	ck := edge.NewCookies([]byte("0123456789abcdef0123456789abcdef"))
	ck.SameSite = http.SameSiteNoneMode
	var priv ed25519.PrivateKey
	e := newEnvWith(t, []Option{WithEdgeGrants(ck)}, withAuth(&priv))
	e.opPriv = priv
	k := newKey("k")
	e.mkNS("sec", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	e.mkNS("sec-x", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	admin := e.grant(k, "user:root", []string{"sec", "sec-x"}, allVerbs)
	e.create("sec", "a", map[string]any{"v": 1.0}, admin)
	e.create("sec-x", "a", map[string]any{"v": 1.0}, admin)
	r := e.do(req{method: "POST", path: "/edge-grants", bearer: e.grant(k, "user:bob", []string{"sec"}, []string{"read"})})
	expect(t, r, 200)
	for _, sc := range r.H.Values("Set-Cookie") {
		for _, attr := range []string{"Secure", "HttpOnly", "SameSite=None", "Max-Age=900"} {
			if !strings.Contains(sc, "; "+attr) {
				t.Errorf("%s: no %s", sc, attr)
			}
		}
	}
	cs := edgeCookies(t, r)
	nc, rc := cs["/ns/sec"], cs["/r/sec"]
	if nc == nil || rc == nil || len(cs) != 2 {
		t.Fatalf("cookies %v", r.H.Values("Set-Cookie"))
	}
	expect(t, e.do(req{method: "GET", path: "/ns/sec", hdr: cookieHdr(nc)}), 302)
	expect(t, e.do(req{method: "GET", path: "/ns/sec/log", hdr: cookieHdr(nc)}), 302)
	expect(t, e.do(req{method: "GET", path: "/r/sec/a/log", hdr: cookieHdr(rc)}), 302)
	// Path matching is by segment: not another namespace sharing the prefix.
	expect(t, e.do(req{method: "GET", path: "/ns/sec-x", hdr: cookieHdr(nc)}), 401)
	expect(t, e.do(req{method: "GET", path: "/r/sec-x/a", hdr: cookieHdr(rc)}), 401)
}

// v0.47 §C.5: no edge grant outlives its exp. A cookie is verified when
// a request starts, so an event stream opened under one checks its exp at
// each fetch, and ends there as one under the grant in Authorization does.
func TestV047EdgeCookieStreamEndsAtExp(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	short := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"exp": t0.Add(5 * time.Minute).Format(time.RFC3339)})
	r := e.do(req{method: "POST", path: "/edge-grants", bearer: short})
	expect(t, r, 200)
	cs := edgeCookies(t, r)
	nsEvents, resp, _ := e.openSSE("/ns/sec/events", cookieHdr(cs["/ns/sec"]))
	if resp.StatusCode != 200 {
		t.Fatalf("namespace stream: %d", resp.StatusCode)
	}
	next(t, nsEvents) // the genesis entry
	next(t, nsEvents) // a's create
	resEvents, resp, _ := e.openSSE("/r/sec/a/events?since="+a, cookieHdr(cs["/r/sec"]))
	if resp.StatusCode != 200 {
		t.Fatalf("resource stream: %d", resp.StatusCode)
	}

	e.clock.Advance(5 * time.Minute)
	e.appendRev("sec", "a", a, ops(op("replace", "/v", 2.0)), f.adminG)
	for name, ch := range map[string]<-chan sseEvent{"namespace": nsEvents, "resource": resEvents} {
		select {
		case ev, ok := <-ch:
			if ok {
				t.Errorf("%s stream delivered %s %s past the edge grant's exp", name, ev.event, ev.data)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s stream still open past the edge grant's exp", name)
		}
	}
}

// v0.47 §6.1: a schemaReads read is made with the grant in Authorization,
// since no edge cookie covers it. An edge that knows only prefixes
// forwards it undecided, so the origin serves it without the edge's
// verification, private and no-store for shared caches; other private
// reads still need the verification.
func TestV047SchemaReadsBehindEdge(t *testing.T) {
	t.Parallel()
	v, err := edge.New([]byte("s3cret"), "")
	if err != nil {
		t.Fatal(err)
	}
	var priv ed25519.PrivateKey
	e := newEnvWith(t, []Option{WithEdge(v)}, withAuth(&priv))
	e.opPriv = priv
	sk, ck, rk := newKey("sk"), newKey("ck"), newKey("rk")
	e.mkNS("schemas", map[string]any{"read": "grant", "keys": []any{sk.entry("*")}, "schemaReads": map[string]any{"for": []any{"content"}}})
	e.mkNS("content", map[string]any{"read": "grant", "keys": []any{ck.entry("*"), rk.entry("read")}})
	sg := e.grant(sk, "user:admin", []string{"schemas"}, allVerbs)
	cg := e.grant(ck, "user:admin", []string{"content"}, allVerbs)
	s := e.create("schemas", "s", map[string]any{"$schema": dialect, "type": "object"}, sg)
	sRef := "/r/schemas/s/rev/" + s
	e.create("content", "doc", map[string]any{"$schema": sRef, "v": 1.0}, cg)
	reader := e.grant(rk, "user:li", []string{"content"}, []string{"read"})
	verified := map[string]string{edge.DefaultHeader: "s3cret"}

	for _, hdr := range []map[string]string{nil, verified} {
		r := e.do(req{method: "GET", path: sRef, bearer: reader, hdr: hdr})
		expect(t, r, 200)
		if r.H.Get("Cache-Control") != "private, max-age=300" || r.H.Get("CDN-Cache-Control") != "no-store" || r.H.Get("Surrogate-Control") != "no-store" {
			t.Fatalf("referrer read (%v): %v", hdr, r.H)
		}
	}
	// A reader of schemas reads it as any private read: through the edge,
	// with its lifetime.
	expectCode(t, e.do(req{method: "GET", path: sRef, bearer: sg}), 403, edge.Code)
	r := e.do(req{method: "GET", path: sRef, bearer: sg, hdr: verified})
	expect(t, r, 200)
	if r.H.Get("CDN-Cache-Control") != "max-age=86400, s-maxage=31536000, immutable" {
		t.Fatalf("schemas reader: %v", r.H)
	}
	// An edge cookie of the referrer's namespace doesn't cover the path.
	g := e.do(req{method: "POST", path: "/edge-grants", bearer: reader})
	expect(t, g, 200)
	h := cookieHdr(edgeCookies(t, g)["/r/content"])
	h[edge.DefaultHeader] = "s3cret"
	expect(t, e.do(req{method: "GET", path: "/r/content/doc", hdr: h}), 302)
	expect(t, e.do(req{method: "GET", path: sRef, hdr: h}), 401)
}
