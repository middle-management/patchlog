package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
)

// issueGrants posts grants to POST /edge-grants in the body (§C.5).
func (e *tenv) issueGrants(grants ...string) *resp {
	e.t.Helper()
	return e.do(req{method: "POST", path: "/edge-grants", body: map[string]any{"grants": grants}})
}

// prefixesOf are the prefixes of a POST /edge-grants answer, space-joined.
func prefixesOf(t *testing.T, r *resp) string {
	t.Helper()
	ps, _ := r.Obj()["prefixes"].([]any)
	var out []string
	for _, p := range ps {
		out = append(out, p.(string))
	}
	return strings.Join(out, " ")
}

// expectNoCookies fails if a refusal set any cookie (§C.5, all or nothing).
func expectNoCookies(t *testing.T, name string, r *resp) {
	t.Helper()
	if cs := r.H.Values("Set-Cookie"); len(cs) > 0 {
		t.Errorf("%s: cookies set on a refusal: %v", name, cs)
	}
}

// v0.50 §C.5 "Issuing them": several grants as { "grants": [ … ] } in the
// body, 1 to 50 and no Authorization, 400 otherwise; without a body the
// grant in Authorization, as before.
func TestV050EdgeGrantsBodyShape(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	reader := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"})
	many := make([]any, 51)
	for i := range many {
		many[i] = reader
	}
	huge := strings.Repeat("A", 12000) // past the 8 KiB grantSize
	for _, c := range []struct {
		name   string
		q      req
		status int
		code   string
	}{
		{"with Authorization", req{body: map[string]any{"grants": []any{reader}}, bearer: reader}, 400, "bad_input"},
		{"with another Authorization", req{body: map[string]any{"grants": []any{reader}}, hdr: map[string]string{"Authorization": "Basic eDp5"}}, 400, "bad_input"},
		{"no grants", req{body: map[string]any{"grants": []any{}}}, 400, "bad_input"},
		{"51 grants", req{body: map[string]any{"grants": many}}, 400, "bad_input"},
		{"not a string", req{body: map[string]any{"grants": []any{reader, 1.0}}}, 400, "bad_input"},
		{"null", req{body: map[string]any{"grants": []any{nil}}}, 400, "bad_input"},
		{"extra member", req{body: map[string]any{"grants": []any{reader}, "exp": "x"}}, 400, "bad_input"},
		{"no grants member", req{body: map[string]any{"grant": reader}}, 400, "bad_input"},
		{"grants not an array", req{body: map[string]any{"grants": reader}}, 400, "bad_input"},
		{"an array", req{body: []any{reader}}, 400, "bad_input"},
		{"malformed JSON", req{raw: `{"grants": [`}, 400, "bad_input"},
		// More than room for 50 grants: over the exchange's limits (§12).
		{"too large", req{raw: `{"grants": ["` + strings.Repeat("A", 600<<10) + `"]}`}, 400, "bad_input"},
		{"a grant too large", req{body: map[string]any{"grants": []any{reader, huge}}}, 413, "limit"},
		{"not a grant", req{body: map[string]any{"grants": []any{reader, "x"}}}, 401, "unauthenticated"},
		{"empty token", req{body: map[string]any{"grants": []any{""}}}, 401, "unauthenticated"},
		{"no body, no Authorization", req{}, 401, "unauthenticated"},
		// A cross-site form posts text/plain without a preflight.
		{"text/plain", req{body: map[string]any{"grants": []any{reader}}, ct: "text/plain"}, 415, "bad_input"},
		{"form", req{raw: `{"grants":["` + reader + `"]}`, ct: "application/x-www-form-urlencoded"}, 415, "bad_input"},
		{"text/plain form shape", req{raw: `{"grants":["` + reader + `"]}` + "\r\n", ct: "text/plain", hdr: map[string]string{"Origin": "https://evil.example"}}, 415, "bad_input"},
		{"no Content-Type", req{raw: `{"grants":["` + reader + `"]}`, ct: " "}, 415, "bad_input"},
	} {
		c.q.method, c.q.path = "POST", "/edge-grants"
		r := e.do(c.q)
		if r.Code != c.status || r.Str("code") != c.code {
			t.Errorf("%s: want %d %s: %d %s", c.name, c.status, c.code, r.Code, r.Body)
		}
		expectNoCookies(t, c.name, r)
	}
	// One grant in the body answers as in Authorization; 50 are allowed.
	for _, r := range []*resp{
		e.do(req{method: "POST", path: "/edge-grants", bearer: reader}),
		e.issueGrants(reader),
		e.issueGrants("biscuit:" + reader),
		e.issueGrants(" " + reader + "\n"), // trimmed, as in Authorization
		e.do(req{method: "POST", path: "/edge-grants", raw: `{"grants":["` + reader + `"]}`, ct: "Application/JSON; charset=utf-8"}),
		e.do(req{method: "POST", path: "/edge-grants", body: map[string]any{"grants": many[:50]}}),
	} {
		expect(t, r, 200)
		if got := prefixesOf(t, r); got != "/r/sec /ns/sec" || len(r.H.Values("Set-Cookie")) != 2 {
			t.Fatalf("prefixes %s, cookies %v", got, r.H.Values("Set-Cookie"))
		}
	}
}

// v0.50 §C.5: the cookies of several grants. Prefixes come in the order
// the grants first give them, once each; a prefix several grants give
// gets one cookie lasting as long as the longest, and the body's exp is
// the earliest. Each grant's last until its exp or 15 minutes.
func TestV050EdgeGrantsSeveral(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	e.mkNS("sec2", map[string]any{"read": "grant", "keys": []any{f.admin.entry("*"), f.issuer.entry("read")}})
	admin := e.grant(f.admin, "user:root", []string{"sec2"}, allVerbs)
	a := e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	e.create("sec", "b", map[string]any{"v": 1.0}, f.adminG)
	e.create("sec2", "a", map[string]any{"v": 2.0}, admin)
	exp := func(d time.Duration) map[string]any { return map[string]any{"exp": t0.Add(d).Format(time.RFC3339)} }
	fix := func(name string) map[string]any {
		return map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": name}}}
	}
	read := []string{"read"}
	g5 := e.grant(f.issuer, "user:bob", []string{"sec"}, read, exp(5*time.Minute))
	g10 := e.grant(f.issuer, "user:carol", []string{"sec"}, read, exp(10*time.Minute))
	g2 := e.grant(f.issuer, "user:bob", []string{"sec2"}, read)
	fixedA := e.grant(f.issuer, "user:bob", []string{"sec"}, read, fix("a"), exp(2*time.Minute))
	maxAge := func(r *resp) map[string]int {
		out := map[string]int{}
		for p, c := range edgeCookies(t, r) {
			out[p] = c.MaxAge
		}
		return out
	}

	for _, c := range []struct {
		name     string
		grants   []string
		prefixes string
		maxAge   map[string]int
	}{
		{"two namespaces", []string{g5, g2}, "/r/sec /ns/sec /r/sec2 /ns/sec2",
			map[string]int{"/r/sec": 300, "/ns/sec": 300, "/r/sec2": 900, "/ns/sec2": 900}},
		{"same prefixes, shorter first", []string{g5, g10}, "/r/sec /ns/sec",
			map[string]int{"/r/sec": 600, "/ns/sec": 600}},
		{"same prefixes, longer first", []string{g10, g5}, "/r/sec /ns/sec",
			map[string]int{"/r/sec": 600, "/ns/sec": 600}},
		{"a grant twice", []string{g5, g5}, "/r/sec /ns/sec",
			map[string]int{"/r/sec": 300, "/ns/sec": 300}},
		{"capped at 15 minutes", []string{g2, g10}, "/r/sec2 /ns/sec2 /r/sec /ns/sec",
			map[string]int{"/r/sec2": 900, "/ns/sec2": 900, "/r/sec": 600, "/ns/sec": 600}},
		{"fixed and namespace-wide", []string{fixedA, g10}, "/r/sec/a /r/sec /ns/sec",
			map[string]int{"/r/sec/a": 120, "/r/sec": 600, "/ns/sec": 600}},
	} {
		r := e.issueGrants(c.grants...)
		expect(t, r, 200)
		if got := prefixesOf(t, r); got != c.prefixes {
			t.Errorf("%s: prefixes %s", c.name, got)
		}
		if n := len(r.H.Values("Set-Cookie")); n != len(c.maxAge) {
			t.Errorf("%s: %d Set-Cookie: %v", c.name, n, r.H.Values("Set-Cookie"))
		}
		if got := maxAge(r); fmt.Sprint(got) != fmt.Sprint(c.maxAge) {
			t.Errorf("%s: Max-Age %v", c.name, got)
		}
		// The body's exp is the earliest of the cookies'.
		if want := t0.Add(shortest(c.maxAge)).Format(time.RFC3339); r.Str("exp") != want {
			t.Errorf("%s: exp %s, want %s", c.name, r.Str("exp"), want)
		}
	}

	// Reads with the cookies, each until its own exp, which is in its
	// value as in its Max-Age (§C.5 "Format").
	r := e.issueGrants(g5, g10, g2)
	expect(t, r, 200)
	cs := edgeCookies(t, r)
	if exp := cookieExp(t, cs["/r/sec"]); exp != t0.Add(10*time.Minute).Unix() {
		t.Fatalf("/r/sec cookie exp %d", exp)
	}
	h := e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(cs["/r/sec"])})
	expect(t, h, 302)
	expect(t, e.do(req{method: "GET", path: "/r/sec/a/rev/" + a, hdr: cookieHdr(cs["/r/sec"])}), 200)
	expect(t, e.do(req{method: "GET", path: "/r/sec2/a", hdr: cookieHdr(cs["/r/sec2"])}), 302)
	expect(t, e.do(req{method: "GET", path: "/ns/sec2", hdr: cookieHdr(cs["/ns/sec2"])}), 302)
	expect(t, e.do(req{method: "GET", path: "/r/sec2/a", hdr: cookieHdr(cs["/r/sec"])}), 401)
	// Past g5's exp, the shared cookie lasts as long as g10.
	e.clock.Advance(7 * time.Minute)
	expect(t, e.do(req{method: "GET", path: "/r/sec/b", hdr: cookieHdr(cs["/r/sec"])}), 302)
	e.clock.Advance(3 * time.Minute)
	expect(t, e.do(req{method: "GET", path: "/r/sec/b", hdr: cookieHdr(cs["/r/sec"])}), 401)
	expect(t, e.do(req{method: "GET", path: "/r/sec2/a", hdr: cookieHdr(cs["/r/sec2"])}), 302)
}

// shortest is the shortest of Max-Age values, as a duration.
func shortest(maxAge map[string]int) time.Duration {
	out := edge.MaxGrantTTL
	for _, s := range maxAge {
		out = min(out, time.Duration(s)*time.Second)
	}
	return out
}

// cookieExp is the exp claim of an edge-grant cookie in the default format.
func cookieExp(t *testing.T, c *http.Cookie) int64 {
	t.Helper()
	p, _, _ := strings.Cut(c.Value, ".")
	body, err := base64.RawURLEncoding.DecodeString(p)
	var cl struct{ Exp int64 }
	if err != nil || json.Unmarshal(body, &cl) != nil {
		t.Fatalf("cookie %s", c.Value)
	}
	return cl.Exp
}

// v0.50 §C.5: all or nothing across every grant sent: 401 if any
// namespace of any grant would be 401, else 403, and 410 purged only when
// every one refused is purged, naming in ns and head the first refused in
// the order of the grants and their root blocks.
func TestV050EdgeGrantsAllOrNothing(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	admin := e.grant(f.admin, "user:root", []string{"p1", "p2"}, allVerbs)
	heads := map[string]string{}
	for _, ns := range []string{"p1", "p2"} {
		e.mkNS(ns, map[string]any{"read": "grant", "keys": []any{f.admin.entry("*"), f.issuer.entry("read", "append")}})
		expect(t, e.patchNS(ns, ops(op("add", "/frozen", true)), admin), 201)
		expect(t, e.do(req{method: "POST", path: "/ns/" + ns + "/purge", ifMatch: e.nsHead(ns, admin), bearer: admin}), 204)
		heads[ns] = e.nsHead(ns, admin)
	}
	read := []string{"read"}
	ok := e.grant(f.issuer, "user:bob", []string{"sec"}, read)
	bad := e.grant(newKey("issuer"), "user:bob", []string{"sec"}, read) // doesn't verify
	noRead := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"append"})
	star := mint(t, e.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"*"}, "can": []any{"read"}, "exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	missing := e.grant(f.issuer, "user:bob", []string{"nope"}, read)
	p1 := e.grant(f.issuer, "user:bob", []string{"p1"}, read)
	p2 := e.grant(f.issuer, "user:bob", []string{"p2"}, read)
	p21 := e.grant(f.issuer, "user:bob", []string{"p2", "p1"}, read)
	secP1 := e.grant(f.issuer, "user:bob", []string{"sec", "p1"}, read)
	for _, c := range []struct {
		name   string
		grants []string
		status int
		ns     string // of a 410
	}{
		{"all issue", []string{ok, ok}, 200, ""},
		{"one doesn't verify", []string{ok, bad}, 401, ""},
		{"not a grant", []string{"x", ok}, 401, ""},
		{"403 then 401", []string{noRead, bad}, 401, ""},
		{"401 then 403", []string{missing, noRead}, 401, ""},
		{"star", []string{ok, star}, 403, ""},
		{"star then 401", []string{star, missing}, 401, ""},
		{"no read", []string{ok, noRead}, 403, ""},
		{"purged and 403", []string{p1, noRead}, 403, ""},
		{"purged and 401", []string{p1, missing}, 401, ""},
		{"one purged", []string{ok, p1}, 410, "p1"},
		{"both purged", []string{p2, p1}, 410, "p2"},
		{"both purged, other order", []string{p1, p2}, 410, "p1"},
		{"root order", []string{p21}, 410, "p2"},
		{"one grant issues in one", []string{secP1, p2}, 410, "p1"},
		{"after a grant that issues", []string{ok, p21, p1}, 410, "p2"},
	} {
		r := e.issueGrants(c.grants...)
		if r.Code != c.status {
			t.Errorf("%s: want %d: %d %s", c.name, c.status, r.Code, r.Body)
			continue
		}
		if c.status == 410 && (r.Str("code") != "purged" || r.Str("ns") != c.ns || r.Str("head") != heads[c.ns]) {
			t.Errorf("%s: want purged %s %s: %s", c.name, c.ns, heads[c.ns], r.Body)
		}
		if c.status != 200 {
			expectNoCookies(t, c.name, r)
		}
	}
}

// v0.50 §C.5: a grant's rules fix /resource when a rule of its blocks or
// its key's scope, at top level or inside all, tests it against one name
// (value, or compare eq a literal) or a finite set (a schema of only
// enum, or compare in a literal array); several such rules fix it to the
// names all allow, one prefix per name. Any other reference to /resource,
// an empty set or an invalid name is 403. v0.51: an exchange that would
// issue more than 100 distinct prefixes is 400, once the grants have
// verified.
func TestV050EdgeGrantsFiniteSets(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	e.mkNS("sec2", map[string]any{"read": "grant", "keys": []any{f.admin.entry("*"), f.issuer.entry("read")}})
	for _, n := range []string{"a", "b", "c", "d"} {
		e.create("sec", n, map[string]any{"v": n}, f.adminG)
	}
	test := func(v any) map[string]any { return map[string]any{"op": "test", "path": "/resource", "value": v} }
	enum := func(vs ...any) map[string]any {
		return map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": vs}}
	}
	compare := func(op string, v any) map[string]any {
		return map[string]any{"op": "compare", "path": "/resource", op: map[string]any{"value": v}}
	}
	all := func(rules ...any) map[string]any { return map[string]any{"all": rules} }
	bob := map[string]any{"op": "test", "path": "/principal/id", "value": "user:bob"}
	names := func(prefix string, n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = fmt.Sprintf("%s%03d", prefix, i)
		}
		return out
	}
	under := func(p string, vs []any) string {
		var out []string
		for _, v := range vs {
			out = append(out, p+v.(string))
		}
		return strings.Join(out, " ")
	}
	issue := func(ns []string, rules ...any) *resp {
		return e.do(req{method: "POST", path: "/edge-grants", bearer: e.grant(f.issuer, "user:bob", ns, []string{"read"}, map[string]any{"rules": rules})})
	}
	sec := []string{"sec"}
	for _, c := range []struct {
		name     string
		rules    []any
		prefixes string // "" for 403
	}{
		{"value", []any{test("a")}, "/r/sec/a"},
		{"compare eq", []any{compare("eq", "a")}, "/r/sec/a"},
		{"enum", []any{enum("a", "b", "c")}, "/r/sec/a /r/sec/b /r/sec/c"},
		{"enum with duplicates", []any{enum("b", "a", "b")}, "/r/sec/b /r/sec/a"},
		{"compare in", []any{compare("in", []any{"a", "b"})}, "/r/sec/a /r/sec/b"},
		{"value and enum", []any{test("a"), enum("a", "b")}, "/r/sec/a"},
		{"enum and in", []any{enum("c", "b", "a"), compare("in", []any{"a", "c", "d"})}, "/r/sec/c /r/sec/a"},
		{"inside all", []any{all(enum("a", "b"), bob)}, "/r/sec/a /r/sec/b"},
		{"nested all", []any{all(all(compare("in", []any{"a", "b"})), enum("b", "c"))}, "/r/sec/b"},
		{"a rule on the principal beside", []any{bob, enum("a", "d")}, "/r/sec/a /r/sec/d"},
		{"100 names", []any{enum(names("n", 100)...)}, under("/r/sec/", names("n", 100))},
		{"disjoint", []any{test("a"), enum("b")}, ""},
		{"empty enum", []any{enum()}, ""},
		{"empty in", []any{compare("in", []any{})}, ""},
		{"invalid name", []any{enum("a", "no/slash")}, ""},
		{"empty name", []any{test("")}, ""},
		{"not a string", []any{enum("a", 1.0)}, ""},
		{"invalid name intersected away", []any{test("a"), enum("a", "..")}, ""},
		{"enum with another keyword", []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"a"}, "type": "string"}}}, ""},
		{"schema without enum", []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"const": "a"}}}, ""},
		{"enum not an array", []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": "a"}}}, ""},
		{"in a path", []any{map[string]any{"op": "compare", "path": "/resource", "in": map[string]any{"path": "/principal/attrs/docs"}}}, ""},
		{"eq a path", []any{map[string]any{"op": "compare", "path": "/resource", "eq": map[string]any{"path": "/principal/id"}}}, ""},
		{"in a string", []any{compare("in", "a")}, ""},
		{"lt", []any{compare("lt", "a")}, ""},
		{"exists", []any{map[string]any{"op": "test", "path": "/resource", "exists": true}}, ""},
		{"inside any", []any{map[string]any{"any": []any{enum("a", "b")}}}, ""},
		{"inside not", []any{map[string]any{"not": test("a")}}, ""},
		{"inside if", []any{map[string]any{"if": []any{bob}, "then": []any{test("a")}}}, ""},
		{"all beside a fixing rule refers otherwise", []any{all(enum("a"), map[string]any{"not": test("b")})}, ""},
		// An invalid literal is 403 however many names the rest give.
		{"101 names and an invalid one", []any{enum(append(names("n", 101), "no/slash")...)}, ""},
		{"101 names, an invalid one intersected away", []any{enum(names("n", 101)...), enum(append(names("n", 101), "..")...)}, ""},
	} {
		r := issue(sec, c.rules...)
		if c.prefixes == "" {
			if r.Code != 403 {
				t.Errorf("%s: want 403: %d %s", c.name, r.Code, r.Body)
			}
			expectNoCookies(t, c.name, r)
			continue
		}
		if r.Code != 200 {
			t.Errorf("%s: %d %s", c.name, r.Code, r.Body)
			continue
		}
		if got := prefixesOf(t, r); got != c.prefixes || len(r.H.Values("Set-Cookie")) != len(strings.Fields(got)) {
			t.Errorf("%s: prefixes %s, cookies %v", c.name, got, r.H.Values("Set-Cookie"))
		}
	}

	// Each cookie reads its own resource only.
	r := issue(sec, enum("a", "b", "c"))
	expect(t, r, 200)
	cs := edgeCookies(t, r)
	expect(t, e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(cs["/r/sec/a"])}), 302)
	expect(t, e.do(req{method: "GET", path: "/r/sec/c/log", hdr: cookieHdr(cs["/r/sec/c"])}), 302)
	expect(t, e.do(req{method: "GET", path: "/r/sec/b", hdr: cookieHdr(cs["/r/sec/a"])}), 401)
	expect(t, e.do(req{method: "GET", path: "/r/sec/d", hdr: cookieHdr(cs["/r/sec/a"])}), 401)
	expect(t, e.do(req{method: "GET", path: "/ns/sec", hdr: cookieHdr(cs["/r/sec/a"])}), 401)

	// A grant naming two namespaces gets the names in each.
	r = issue([]string{"sec", "sec2"}, enum("a", "b"))
	expect(t, r, 200)
	if got := prefixesOf(t, r); got != "/r/sec/a /r/sec/b /r/sec2/a /r/sec2/b" {
		t.Errorf("two namespaces: %s", got)
	}

	// v0.51: the cap counts distinct prefixes over all grants of the
	// request, two for a namespace-wide grant, and is 400.
	g := func(ns []string, vs []any) string {
		return e.grant(f.issuer, "user:bob", ns, []string{"read"}, map[string]any{"rules": []any{enum(vs...)}})
	}
	wide := e.grant(f.issuer, "user:bob", sec, []string{"read"})
	for _, c := range []struct {
		name   string
		grants []string
		status int
		n      int
	}{
		{"101 names", []string{g(sec, names("n", 101))}, 400, 0},
		{"50 and 50", []string{g(sec, names("a", 50)), g(sec, names("b", 50))}, 200, 100},
		{"50 in two namespaces", []string{g([]string{"sec", "sec2"}, names("a", 50))}, 200, 100},
		{"60 in two namespaces", []string{g([]string{"sec", "sec2"}, names("a", 60))}, 400, 0},
		{"the same 60 twice", []string{g(sec, names("a", 60)), g(sec, names("a", 60))}, 200, 60},
		{"overlapping 60s", []string{g(sec, names("a", 60)), g(sec, names("a", 80))}, 200, 80},
		{"60 and 60", []string{g(sec, names("a", 60)), g(sec, names("b", 60))}, 400, 0},
		{"100 and 1", []string{g(sec, names("a", 100)), g(sec, names("b", 1))}, 400, 0},
		{"98 and namespace-wide", []string{g(sec, names("a", 98)), wide}, 200, 100},
		{"98 and namespace-wide twice", []string{g(sec, names("a", 98)), wide, wide}, 200, 100},
		{"99 and namespace-wide", []string{g(sec, names("a", 99)), wide}, 400, 0},
		{"100 and namespace-wide", []string{g(sec, names("a", 100)), wide}, 400, 0},
		// A refusal outranks the cap: it applies once the grants verify.
		{"over the cap and a 401", []string{g(sec, names("a", 101)), "x"}, 401, 0},
		{"over the cap and a 403", []string{g(sec, names("a", 101)), e.grant(f.issuer, "user:bob", sec, []string{"append"})}, 403, 0},
		{"over the cap and an invalid name", []string{g(sec, names("a", 101)), g(sec, []any{"a", "no/slash"})}, 403, 0},
	} {
		r := e.issueGrants(c.grants...)
		if r.Code != c.status {
			t.Errorf("%s: want %d: %d %s", c.name, c.status, r.Code, r.Body)
			continue
		}
		if c.status == 400 && r.Str("code") != "bad_input" {
			t.Errorf("%s: %s", c.name, r.Body)
		}
		if n := len(strings.Fields(prefixesOf(t, r))); c.status == 200 && (n != c.n || len(r.H.Values("Set-Cookie")) != c.n) {
			t.Errorf("%s: %d prefixes, want %d", c.name, n, c.n)
		}
		if c.status != 200 {
			expectNoCookies(t, c.name, r)
		}
	}
}

// v0.50 §C.5: the key's scope fixes /resource as the grant's blocks do,
// and a key with readScope "resource" accepts a grant fixing a set.
func TestV050EdgeGrantsKeyScopeSet(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	kr := newKey("kr")
	ks := newKey("ks")
	krEntry := kr.entry("read")
	krEntry["readScope"] = "resource"
	ksEntry := ks.entry("read")
	ksEntry["rules"] = []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"a", "b"}}}}
	e.mkNS("ks", map[string]any{"read": "grant", "keys": []any{f.admin.entry("*"), krEntry, ksEntry}})
	issue := func(k keyPair, rules ...any) *resp {
		extra := map[string]any{}
		if len(rules) > 0 {
			extra["rules"] = rules
		}
		return e.do(req{method: "POST", path: "/edge-grants", bearer: e.grant(k, "user:bob", []string{"ks"}, []string{"read"}, extra)})
	}
	in := func(vs ...any) map[string]any {
		return map[string]any{"op": "compare", "path": "/resource", "in": map[string]any{"value": vs}}
	}
	for _, c := range []struct {
		name     string
		r        *resp
		prefixes string
	}{
		{"key scope", issue(ks), "/r/ks/a /r/ks/b"},
		{"key scope and block", issue(ks, in("b", "c")), "/r/ks/b"},
		{"key scope and a disjoint block", issue(ks, in("c")), ""},
		{"readScope with a set", issue(kr, in("a", "b")), "/r/ks/a /r/ks/b"},
		{"readScope unfixed", issue(kr), ""},
	} {
		if c.prefixes == "" {
			if c.r.Code != 403 {
				t.Errorf("%s: want 403: %d %s", c.name, c.r.Code, c.r.Body)
			}
			continue
		}
		expect(t, c.r, 200)
		if got := prefixesOf(t, c.r); got != c.prefixes {
			t.Errorf("%s: prefixes %s", c.name, got)
		}
	}
}

// v0.52 §C.5, §6.6 (v0.50 drew one token per grant from the write
// bucket): once nothing is refused, the request draws one token, however
// many grants it carries, from the exchangeRate bucket of each distinct
// principal among them, and from no write bucket or allowance. It is 429
// exchangeRate while any of those buckets is empty, and draws nothing
// then, nor on a refusal.
func TestV050EdgeGrantsRateLimits(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, map[string]any{
		"limits": map[string]any{"ratePerPrincipal": map[string]any{"rate": 0.001, "burst": 1}},
		"allowances": []any{map[string]any{
			"sub": "user:al", "kid": "issuer", "bucket": map[string]any{"rate": 0.001, "burst": 1}}},
	}, withExchangeRate(core.Rate{Rate: 0.001, Burst: 2}))
	e := f.tenv
	g := func(sub string) string {
		return e.grant(f.issuer, sub, []string{"sec"}, []string{"read", "create"})
	}
	expectRate := func(name string, r *resp, limit string) {
		t.Helper()
		if r.Code != 429 || r.Str("code") != "rate" || r.Str("limit") != limit || r.H.Get("Retry-After") == "" {
			t.Errorf("%s: want 429 %s: %d %v %s", name, limit, r.Code, r.H, r.Body)
		}
		if ra, _ := r.Obj()["retryAfter"].(float64); ra <= 0 {
			t.Errorf("%s: retryAfter %s", name, r.Body)
		}
		expectNoCookies(t, name, r)
	}
	exchange := func(bearer string) *resp {
		return e.do(req{method: "POST", path: "/edge-grants", bearer: bearer})
	}
	write := func(name, bearer string) *resp {
		return e.do(req{method: "PATCH", path: "/r/sec/" + name, ifNoneMatch: "*", body: addRoot(map[string]any{}), bearer: bearer})
	}

	// Exchanges and writes don't share a bucket: two exchanges empty the
	// exchange bucket and leave the write bucket full, and a write empties
	// the write bucket and leaves the exchange bucket full.
	bob := g("user:bob")
	expect(t, exchange(bob), 200)
	expect(t, exchange(bob), 200)
	expectRate("a third exchange", exchange(bob), "exchangeRate")
	expect(t, write("bob", bob), 201)
	expectRate("a second write", write("bob2", bob), "ratePerPrincipal")
	carol := g("user:carol")
	expect(t, write("carol", carol), 201)
	expect(t, exchange(carol), 200)
	expect(t, exchange(carol), 200)
	expectRate("a third exchange after a write", exchange(carol), "exchangeRate")

	// Several grants of one principal draw one token: after three in one
	// request, one more exchange is admitted.
	dan := g("user:dan")
	danRead := e.grant(f.issuer, "user:dan", []string{"sec"}, []string{"read"})
	expect(t, e.issueGrants(dan, danRead, dan), 200)
	expect(t, exchange(danRead), 200)
	expectRate("dan's third", exchange(dan), "exchangeRate")

	// Several principals each draw one, from their own buckets.
	eve, frank := g("user:eve"), g("user:frank")
	expect(t, e.issueGrants(eve, frank), 200)
	expect(t, exchange(eve), 200)
	expect(t, exchange(frank), 200)
	expectRate("eve's third", exchange(eve), "exchangeRate")
	// An empty bucket of one refuses the request, and draws on no other.
	gil := g("user:gil")
	expectRate("eve empty", e.issueGrants(gil, eve), "exchangeRate")
	expect(t, exchange(gil), 200)
	expect(t, exchange(gil), 200)
	expectRate("gil's third", exchange(gil), "exchangeRate")

	// A refusal draws nothing: neither a 401 nor a 403, nor an exchange
	// over the 100-prefix cap (400).
	hank := g("user:hank")
	expect(t, e.issueGrants(hank, "x"), 401)
	expect(t, e.issueGrants(hank, e.grant(f.issuer, "user:hank", []string{"sec"}, []string{"create"})), 403)
	expect(t, e.issueGrants(hank, e.grant(f.issuer, "user:hank", []string{"sec"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": edgeNames("n", 101)}}}})), 400)
	expect(t, exchange(hank), 200)
	expect(t, exchange(hank), 200)
	expectRate("hank's third", exchange(hank), "exchangeRate")

	// An allowance's bucket is a write bucket: exchanges don't draw on it.
	al := g("user:al")
	expect(t, exchange(al), 200)
	expect(t, exchange(al), 200)
	expectRate("al's third exchange", exchange(al), "exchangeRate")
	expect(t, write("al", al), 201)
	expectRate("al's second write", write("al2", al), "allowance")

	// Buckets are keyed as write buckets are, by the root sub and the key
	// that signed the root block: a narrowing block draws on the same.
	root, err := grant.Mint(map[string]any{"kid": "issuer", "sub": "user:ivy", "ns": []any{"sec"}, "can": []any{"read", "create"},
		"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}, f.issuer.priv)
	if err != nil {
		t.Fatal(err)
	}
	nar, err := root.Narrow(map[string]any{"via": "svc:reader", "can": []any{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	ivy, narrowed := root.Encode(), nar.Encode()
	expect(t, exchange(ivy), 200)
	expect(t, exchange(narrowed), 200)
	expectRate("ivy narrowed", exchange(narrowed), "exchangeRate")
}

// A refused exchange stays cheap, though it draws nothing (§C.5, §6.6):
// fifty grants of a key no namespace lists, each naming as many unknown
// namespaces as 8 KiB holds, are decoded once each, and the first 401
// ends the walk, since nothing after it changes the answer. Decoding each
// grant again per namespace took seconds.
func TestV050EdgeGrantsRefusedCheaply(t *testing.T) {
	t.Parallel()
	e := newAuthFixture(t, nil).tenv
	k := newKey("stranger")
	nss := make([]string, 840)
	for i := range nss {
		nss[i] = fmt.Sprintf("n%d", i)
	}
	gs := make([]string, 50)
	for i := range gs {
		gs[i] = e.grant(k, fmt.Sprintf("user:x%d", i), nss, []string{"read"})
	}
	if len(gs[0]) > 8<<10 {
		t.Fatalf("grant of %d bytes", len(gs[0]))
	}
	start := time.Now()
	r := e.issueGrants(gs...)
	if took := time.Since(start); r.Code != 401 || took > 5*time.Second {
		t.Fatalf("%d in %v", r.Code, took)
	}
	expectNoCookies(t, "stranger", r)
}
