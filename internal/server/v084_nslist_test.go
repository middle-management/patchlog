package server

import (
	"crypto/ed25519"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// v0.84 §7.4 GET /ns?after={name}: the deployment's namespaces, for
// operators (HTTP-69; scenario 75).

// opGrant mints an operator grant whose root block is root over the
// defaults: kid "operator", sub, ns ["*"], can ["config"], an hour's exp. A
// nil value removes a member.
func (e *tenv) opGrant(root map[string]any) *grant.Grant {
	e.t.Helper()
	m := map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"*"}, "can": []any{"config"}, "exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}
	for k, v := range root {
		if v == nil {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	g, err := grant.Mint(m, e.opPriv)
	if err != nil {
		e.t.Fatal(err)
	}
	return g
}

// lister is the operator grant that lists namespaces.
func (e *tenv) lister() string { return e.opGrant(nil).Encode() }

func narrowed(t *testing.T, g *grant.Grant, block map[string]any) string {
	t.Helper()
	n, err := g.Narrow(block)
	if err != nil {
		t.Fatal(err)
	}
	return n.Encode()
}

// nsPage reads a page of GET /ns and returns its rows by name order, and
// next.
func (e *tenv) nsPage(query string, bearer ...string) (rows []map[string]any, next string) {
	e.t.Helper()
	path := "/ns"
	if query != "" {
		path += "?" + query
	}
	r := e.get(path, bearer...)
	expect(e.t, r, 200)
	if cc := r.H.Get("Cache-Control"); cc != "no-store" {
		e.t.Fatalf("GET %s: Cache-Control %q, want no-store", path, cc)
	}
	o := r.Obj()
	arr, ok := o["namespaces"].([]any)
	if !ok {
		e.t.Fatalf("GET %s: no namespaces array in %s", path, r.Body)
	}
	for _, x := range arr {
		rows = append(rows, x.(map[string]any))
	}
	next, _ = o["next"].(string)
	if _, has := o["next"]; has && next == "" {
		e.t.Fatalf("GET %s: an empty next in %s", path, r.Body)
	}
	return rows, next
}

func rowNames(rows []map[string]any) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, r["name"].(string))
	}
	return out
}

func rowOf(t *testing.T, rows []map[string]any, name string) map[string]any {
	t.Helper()
	for _, r := range rows {
		if r["name"] == name {
			return r
		}
	}
	t.Fatalf("no row %s in %v", name, rows)
	return nil
}

// Scenario 75 (CONFORMANCE; HTTP-69, §7.4, §C.4): a grant signed by a *
// key of matches naming ns: ["matches"] is 403; one naming "*" is 401, as
// only operator keys sign "*"; an operator grant naming "*" with config is
// 200, with every namespace listed, branches and purged ones included.
func TestV084NamespacesScenario75(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	star := newKey("star")
	e.mkNS("matches", map[string]any{"keys": []any{star.entry("*")}})
	e.mkNS("old", map[string]any{"keys": []any{star.entry("*")}})
	all := []string{"read", "append", "create", "delete", "config", "branch", "purge", "purge-ns"}
	admin := e.grant(star, "user:admin", []string{"matches"}, all)
	expect(t, e.branch("matches", map[string]any{"name": "matches-next"}, admin), 201)
	e.purgeNSAs("old", e.grant(star, "user:admin", []string{"old"}, all))

	expectCode(t, e.get("/ns", admin), 403, "forbidden")
	expectCode(t, e.get("/ns", e.grant(star, "user:admin", []string{"*"}, all)), 401, "unauthenticated")

	rows, next := e.nsPage("", e.lister())
	if got, want := rowNames(rows), []string{"matches", "matches-next", "old"}; !reflect.DeepEqual(got, want) || next != "" {
		t.Fatalf("namespaces %v next %q, want %v", got, next, want)
	}
	if r := rowOf(t, rows, "old"); r["purged"] != true || r["frozen"] != true {
		t.Fatalf("purged row %v", r)
	}
	if r := rowOf(t, rows, "matches-next"); r["purged"] != false || r["base"].(map[string]any)["ns"] != "matches" {
		t.Fatalf("branch row %v", r)
	}
	if r := rowOf(t, rows, "matches"); r["purged"] != false || r["frozen"] != false || r["base"] != nil || r["created"] != t0.Format("2006-01-02T15:04:05.000Z") {
		t.Fatalf("row %v", r)
	}
}

// HTTP-69 (§7.4): operator grants only, checked in order: the
// request-shape checks (of the URL, then of the grant, §C.2 item 1); a
// block that carries ns without naming "*", 403; a grant that fails
// verification, one whose root kid names no operator key included, and a
// request without credentials, 401; a block without config in its can, or
// a block with rules, 403.
func TestV084NamespacesAuthOrder(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	e.mkNS("main", map[string]any{})
	good := e.lister()
	expect(t, e.get("/ns", good), 200)

	_, otherPriv := grant.GenerateKey()
	forged := func(root map[string]any) string { // signed by a key that isn't the operator's
		m := map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"*"}, "can": []any{"config"}, "exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}
		for k, v := range root {
			if v == nil {
				delete(m, k)
				continue
			}
			m[k] = v
		}
		return mint(t, otherPriv, m)
	}
	passing := []any{map[string]any{"op": "test", "path": "/verb", "value": "config"}}

	// Request-shape errors come first, whatever the credentials: an
	// unknown or repeated query parameter, a prefix that isn't a
	// namespace name, a non-canonical URL.
	for _, bearer := range []string{"", good, "garbage", forged(map[string]any{"ns": []any{"main"}})} {
		for _, q := range []string{"x=1", "after=a&after=b", "prefix=", "prefix=A", "prefix=a.b", "prefix=-a", "prefix=" + strings.Repeat("a", 65), "prefix=a&since=b"} {
			expectCode(t, e.get("/ns?"+q, bearer), 400, "bad_input")
		}
	}
	if c := e.rawGet("/ns/"); c != 400 {
		t.Fatalf("GET /ns/ = %d, want 400", c)
	}

	// The grant's own request-shape checks, before its ns (§C.2 item 1).
	expectCode(t, e.get("/ns", "garbage"), 401, "unauthenticated")
	big := e.opGrant(map[string]any{"ns": []any{"main"}, "attrs": map[string]any{"pad": strings.Repeat("x", 70_000)}}).Encode()
	expectLimit(t, e.get("/ns", big), 413, "grantSize", int64(grantBytes(t, big)), int64(e.e.Limits().GrantSize))

	// 403: a block that carries ns doesn't name "*", before anything is
	// verified, so for a forged or expired grant too.
	for name, g := range map[string]string{
		"ns names a namespace":         e.opGrant(map[string]any{"ns": []any{"main"}}).Encode(),
		"ns names none":                e.opGrant(map[string]any{"ns": []any{}}).Encode(),
		"forged, ns names a namespace": forged(map[string]any{"ns": []any{"main"}}),
		"expired, ns names a namespace": e.opGrant(map[string]any{"ns": []any{"main"},
			"exp": e.clock.Now().Add(-time.Hour).Format(time.RFC3339)}).Encode(),
		"a narrowing block's ns drops *": narrowed(t, e.opGrant(nil), map[string]any{"ns": []any{"main"}}),
		"unknown kid, ns names a namespace": mint(t, otherPriv, map[string]any{"kid": "nobody", "sub": "x", "ns": []any{"main"}, "can": []any{"config"},
			"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}),
	} {
		if r := e.get("/ns", g); r.Code != 403 {
			t.Errorf("%s: %d %s, want 403", name, r.Code, r.Body)
		}
	}

	// 401: no credentials, and a grant that fails verification, before
	// its can and rules are looked at.
	expectCode(t, e.get("/ns"), 401, "unauthenticated")
	for name, g := range map[string]string{
		"forged":                    forged(nil),
		"forged, without config":    forged(map[string]any{"can": []any{"read"}}),
		"forged, with rules":        forged(map[string]any{"rules": passing}),
		"unknown kid":               mint(t, otherPriv, map[string]any{"kid": "nobody", "sub": "x", "ns": []any{"*"}, "can": []any{"config"}, "exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}),
		"expired":                   e.opGrant(map[string]any{"exp": e.clock.Now().Add(-time.Minute).Format(time.RFC3339)}).Encode(),
		"expired, without config":   e.opGrant(map[string]any{"can": []any{"read"}, "exp": e.clock.Now().Add(-time.Minute).Format(time.RFC3339)}).Encode(),
		"not yet valid":             e.opGrant(map[string]any{"nbf": e.clock.Now().Add(time.Minute).Format(time.RFC3339)}).Encode(),
		"a narrowing block expired": narrowed(t, e.opGrant(nil), map[string]any{"can": []any{"config"}, "exp": e.clock.Now().Add(-time.Minute).Format(time.RFC3339)}),
	} {
		r := e.get("/ns", g)
		if r.Code != 401 || r.Obj()["code"] != "unauthenticated" {
			t.Errorf("%s: %d %s, want 401", name, r.Code, r.Body)
		}
		if cc := r.H.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control %q", name, cc)
		}
	}

	// 403: a verified operator grant naming "*" with a block that carries
	// can without config, or non-empty rules, even ones that pass; and
	// one that carries roles, in any block, even an empty list (v0.85;
	// CONFORMANCE Access 79).
	for name, g := range map[string]string{
		"no config":                      e.opGrant(map[string]any{"can": []any{"purge", "purge-ns"}}).Encode(),
		"roles, no can":                  e.opGrant(map[string]any{"can": nil, "roles": []any{"admin"}}).Encode(),
		"rules that pass":                e.opGrant(map[string]any{"rules": passing}).Encode(),
		"a narrowing block drops config": narrowed(t, e.opGrant(map[string]any{"can": []any{"config", "purge"}}), map[string]any{"can": []any{"purge"}}),
		"a narrowing block reads":        narrowed(t, e.opGrant(nil), map[string]any{"can": []any{"read"}}),
		"a narrowing block has rules":    narrowed(t, e.opGrant(nil), map[string]any{"can": []any{"config"}, "rules": passing}),
		"a can-less block has rules":     narrowed(t, e.opGrant(nil), map[string]any{"rules": passing}),
		// A grant that carries roles has no effective role under an
		// operator key, so nothing allows config (§C.2 Invariant).
		"roles":                  e.opGrant(map[string]any{"roles": []any{"admin"}}).Encode(),
		"empty roles":            e.opGrant(map[string]any{"roles": []any{}}).Encode(),
		"roles in a later block": narrowed(t, e.opGrant(nil), map[string]any{"roles": []any{}}),
	} {
		r := e.get("/ns", g)
		if r.Code != 403 || r.Obj()["code"] != "forbidden" {
			t.Errorf("%s: %d %s, want 403", name, r.Code, r.Body)
		}
		if cc := r.H.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control %q", name, cc)
		}
	}

	// 200: every block that carries can lists config and none has a
	// rule; more verbs, "*" beside a name, narrowing blocks that keep
	// config or carry no can, and "rules": [], which is none (v0.85;
	// v0.82 Open 101, settled in v0.85).
	for name, g := range map[string]string{
		"more verbs":      e.opGrant(map[string]any{"can": []any{"config", "purge", "purge-ns"}}).Encode(),
		"* beside a name": e.opGrant(map[string]any{"ns": []any{"main", "*"}}).Encode(),
		"narrowed, config kept": narrowed(t, e.opGrant(map[string]any{"can": []any{"config", "purge"}}),
			map[string]any{"via": "svc:admin", "can": []any{"config"}, "exp": e.clock.Now().Add(time.Minute).Format(time.RFC3339)}),
		"empty rules":                     e.opGrant(map[string]any{"rules": []any{}}).Encode(),
		"a narrowing block without can":   narrowed(t, e.opGrant(nil), map[string]any{"via": "svc:admin"}),
		"a via and exp narrowing block":   narrowed(t, e.opGrant(nil), map[string]any{"via": "svc:admin", "exp": e.clock.Now().Add(time.Minute).Format(time.RFC3339)}),
		"a narrowing block's empty rules": narrowed(t, e.opGrant(nil), map[string]any{"rules": []any{}}),
	} {
		if r := e.get("/ns", g); r.Code != 200 {
			t.Errorf("%s: %d %s, want 200", name, r.Code, r.Body)
		}
	}

	// 401: "*" in a narrowing block's ns, an operator grant's included,
	// before the ns check (§C.1, v0.90; CONFORMANCE Access 103).
	star, err := e.opGrant(map[string]any{"can": []any{"config", "purge"}}).NarrowUnvalidated(map[string]any{"can": []any{"config"}, "ns": []any{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.get("/ns", star.Encode()); r.Code != 401 {
		t.Errorf("a narrowing block naming *: %d %s, want 401", r.Code, r.Body)
	}

	// HEAD answers as GET, without a body.
	if r := e.do(req{method: "HEAD", path: "/ns", bearer: good}); r.Code != 200 || len(r.Body) != 0 || r.H.Get("Cache-Control") != "no-store" {
		t.Fatalf("HEAD /ns: %d %q %v", r.Code, r.Body, r.H)
	}
	// The listing is the only request at /ns.
	for _, m := range []string{"POST", "PATCH", "DELETE", "PUT"} {
		if r := e.do(req{method: m, path: "/ns", bearer: good, hasRaw: true}); r.Code != 405 {
			t.Errorf("%s /ns: %d, want 405", m, r.Code)
		}
	}
	// An operator grant that lists reads nothing else (§C.4).
	expect(t, e.get("/ns/main", good), 401)
}

// purgeDev freezes and purges ns while authentication is disabled.
func (e *tenv) purgeDev(ns string) {
	e.t.Helper()
	if e.get("/ns/" + ns + "/rev/" + e.nsHead(ns)).Obj()["frozen"] != true {
		expect(e.t, e.patchNS(ns, ops(op("add", "/frozen", true)), ""), 201)
	}
	expect(e.t, e.do(req{method: "POST", path: "/ns/" + ns + "/purge", ifMatch: e.nsHead(ns), author: "admin"}), 204)
}

// grantBytes is the decoded length of a bearer, what grantSize measures.
func grantBytes(t *testing.T, bearer string) int {
	t.Helper()
	g, err := grant.Decode(bearer, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	return g.Size()
}

// HTTP-69 (§7.4, §C.4): the root kid must name an operator key in its
// period: 401 before its from and from its until, and with no operator
// key configured at all.
func TestV084NamespacesKeyPeriod(t *testing.T) {
	t.Parallel()
	var opPriv ed25519.PrivateKey
	from, until := t0.Add(time.Hour), t0.Add(3*time.Hour)
	e := newEnv(t, withAuth(&opPriv), func(o *core.Options) {
		o.OperatorKeyHistory = []core.OperatorKeyPeriod{{Kid: "operator", Pub: opPriv.Public().(ed25519.PublicKey), From: from, Until: until}}
	})
	e.opPriv = opPriv
	expectCode(t, e.get("/ns", e.lister()), 401, "unauthenticated")
	// Still 403 first for a grant that doesn't name "*".
	expectCode(t, e.get("/ns", e.opGrant(map[string]any{"ns": []any{"main"}}).Encode()), 403, "forbidden")
	e.clock.Advance(2 * time.Hour)
	if rows, next := e.nsPage("", e.lister()); len(rows) != 0 || next != "" {
		t.Fatalf("an empty deployment lists %v, next %q", rows, next)
	}
	e.clock.Advance(time.Hour)
	expectCode(t, e.get("/ns", e.lister()), 401, "unauthenticated")

	// No operator key configured: nothing verifies.
	n := newEnv(t, func(o *core.Options) { o.AuthDisabled = false })
	n.opPriv = opPriv
	expectCode(t, n.get("/ns", n.lister()), 401, "unauthenticated")
	expectCode(t, n.get("/ns"), 401, "unauthenticated")
}

// HTTP-69 (§7.4): rows in ascending byte order of name, strictly after
// after, a plain bound, paged by logPageSize with next absent on the last
// page; prefix, a namespace name, keeps the names that start with it.
func TestV084NamespacesPaging(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withLogPageSize(3))
	// Byte order: "-" (0x2d) < digits < "_" (0x5f) < letters, which a
	// locale's collation orders otherwise (a_b before a-b, or ignoring
	// both).
	names := []string{"0", "a", "a-b", "a-c", "a0", "a00", "a1", "a_b", "a_c", "aa", "ab", "b", "b-", "b_", "ba", "z9"}
	for _, i := range []int{7, 3, 11, 0, 15, 9, 1, 13, 5, 2, 14, 6, 10, 4, 12, 8} {
		e.mkNS(names[i], map[string]any{})
	}

	// Every page, following next.
	walk := func(query string) (got []string, pages int) {
		t.Helper()
		after := ""
		for {
			q := query
			if after != "" {
				q = strings.TrimPrefix(q+"&after="+url.QueryEscape(after), "&")
			}
			rows, next := e.nsPage(q)
			pages++
			if len(rows) > 3 || len(rows) == 0 && pages > 1 {
				t.Fatalf("page %q of %d rows", q, len(rows))
			}
			got = append(got, rowNames(rows)...)
			if next == "" {
				return got, pages
			}
			if next != got[len(got)-1] {
				t.Fatalf("next %q after a page ending with %q", next, got[len(got)-1])
			}
			if len(rows) != 3 {
				t.Fatalf("a page of %d rows has a next", len(rows))
			}
			after = next
		}
	}
	got, pages := walk("")
	if !reflect.DeepEqual(got, names) {
		t.Fatalf("order %v\nwant  %v", got, names)
	}
	if pages != 6 { // 16 rows in pages of 3
		t.Fatalf("%d pages", pages)
	}
	// A deployment of exactly a page's rows has no next.
	if got, pages := walk("prefix=b"); !reflect.DeepEqual(got, []string{"b", "b-", "b_", "ba"}) || pages != 2 {
		t.Fatalf("prefix b: %v in %d pages", got, pages)
	}
	if got, pages := walk("prefix=a0"); !reflect.DeepEqual(got, []string{"a0", "a00"}) || pages != 1 {
		t.Fatalf("prefix a0: %v in %d pages", got, pages)
	}
	if rows, next := e.nsPage("prefix=a-"); !reflect.DeepEqual(rowNames(rows), []string{"a-b", "a-c"}) || next != "" {
		t.Fatalf("prefix a-: %v %q", rowNames(rows), next)
	}
	if rows, next := e.nsPage("after=aa"); !reflect.DeepEqual(rowNames(rows), []string{"ab", "b", "b-"}) || next != "b-" {
		t.Fatalf("after aa: %v %q", rowNames(rows), next)
	}
	// The last page of exactly three rows has no next.
	if rows, next := e.nsPage("after=b-"); !reflect.DeepEqual(rowNames(rows), []string{"b_", "ba", "z9"}) || next != "" {
		t.Fatalf("after b-: %v %q", rowNames(rows), next)
	}

	// after is a plain bound: strictly after, a name or not, whatever it
	// holds.
	for after, want := range map[string][]string{
		"":         {"0", "a", "a-b"},
		"a":        {"a-b", "a-c", "a0"},
		"a-":       {"a-b", "a-c", "a0"},
		"a-b":      {"a-c", "a0", "a00"},
		"a/":       {"a0", "a00", "a1"},
		"A":        {"a", "a-b", "a-c"},
		"a9":       {"a_b", "a_c", "aa"},
		"a~":       {"b", "b-", "b_"},
		"b_zzz":    {"ba", "z9"},
		"z9":       {},
		"zz":       {},
		"~":        {},
		"~b":       {},
		"a b":      {"a-b", "a-c", "a0"},
		"a\x00z":   {"a-b", "a-c", "a0"},
		"a\xffz":   {"b", "b-", "b_"},
		"aé":       {"b", "b-", "b_"},
		"a_b\x00":  {"a_c", "aa", "ab"},
		"-":        {"0", "a", "a-b"},
		"not a ns": {"z9"},
	} {
		rows, _ := e.nsPage("after=" + url.QueryEscape(after))
		if got := rowNames(rows); !reflect.DeepEqual(got, want) {
			t.Errorf("after %q: %v, want %v", after, got, want)
		}
	}

	// prefix with after: an after below the prefix starts at it, one
	// inside it bounds, one above it ends the listing.
	for q, want := range map[string][]string{
		"prefix=a_&after=a":    {"a_b", "a_c"},
		"prefix=a_&after=a_b":  {"a_c"},
		"prefix=a_&after=a_bz": {"a_c"},
		"prefix=a_&after=b":    {},
		"prefix=a&after=a1":    {"a_b", "a_c", "aa"},
		"prefix=zz":            {},
		"prefix=a-b":           {"a-b"},
	} {
		rows, _ := e.nsPage(q)
		if got := rowNames(rows); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v, want %v", q, got, want)
		}
	}

	// A page is sized by logPageSize whatever the rows are: purged
	// namespaces and branches count as any other.
	e.purgeDev("a-c")
	expect(t, e.branch("a0", map[string]any{"name": "a-d"}, "alice"), 201)
	if rows, next := e.nsPage("after=a"); !reflect.DeepEqual(rowNames(rows), []string{"a-b", "a-c", "a-d"}) || next != "a-d" ||
		rows[1]["purged"] != true || rows[2]["base"].(map[string]any)["ns"] != "a0" {
		t.Fatalf("after a: %v %q", rows, next)
	}
}

// HTTP-69 (§7.4, §6.6): a page is logPageSize rows by default, 1,000.
func TestV084NamespacesDefaultPage(t *testing.T) {
	if testing.Short() {
		t.Skip("creates over a thousand namespaces")
	}
	t.Parallel()
	e := newEnv(t)
	const n = 1003
	for i := 0; i < n; i++ {
		e.mkNS(fmt.Sprintf("n%04d", i), map[string]any{})
	}
	rows, next := e.nsPage("")
	if len(rows) != 1000 || next != "n0999" {
		t.Fatalf("%d rows, next %q", len(rows), next)
	}
	rows, next = e.nsPage("after=" + next)
	if got := rowNames(rows); !reflect.DeepEqual(got, []string{"n1000", "n1001", "n1002"}) || next != "" {
		t.Fatalf("last page %v, next %q", got, next)
	}
}

// CONFORMANCE Access 80 (§7.4, §C.2 item 1; v0.85): an operator grant
// naming "*" that its operator key's scope doesn't allow is 403 at GET
// /ns, as on any other request, between the 401s and the config check; the
// same grant expired is 401.
func TestV085NamespacesKeyScope(t *testing.T) {
	t.Parallel()
	pub, priv := grant.GenerateKey()
	e := newEnv(t, func(o *core.Options) {
		ks, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": pub,
			"can": []any{"config"}, "sub": "op:.*", "maxTtl": "PT2H"}}))
		if err != nil {
			panic(err)
		}
		o.OperatorKeys = ks
		o.AuthDisabled = false
	})
	e.opPriv = priv
	expect(t, e.get("/ns", e.lister()), 200)
	in := func(d time.Duration) string { return e.clock.Now().Add(d).Format(time.RFC3339) }
	for name, g := range map[string]string{
		"sub":                      e.opGrant(map[string]any{"sub": "user:eve"}).Encode(),
		"maxTtl":                   e.opGrant(map[string]any{"exp": in(3 * time.Hour)}).Encode(),
		"can":                      e.opGrant(map[string]any{"can": []any{"config", "purge"}}).Encode(),
		"sub, and no config":       e.opGrant(map[string]any{"sub": "user:eve", "can": []any{"purge"}}).Encode(),
		"sub, narrowed to nothing": narrowed(t, e.opGrant(map[string]any{"sub": "user:eve"}), map[string]any{"can": []any{}}),
	} {
		r := e.get("/ns", g)
		if r.Code != 403 || r.Obj()["code"] != "forbidden" || r.H.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %s %v, want 403", name, r.Code, r.Body, r.H)
		}
	}
	for name, g := range map[string]string{
		"sub, expired":       e.opGrant(map[string]any{"sub": "user:eve", "exp": in(-time.Minute)}).Encode(),
		"sub, not yet valid": e.opGrant(map[string]any{"sub": "user:eve", "nbf": in(time.Minute)}).Encode(),
	} {
		if r := e.get("/ns", g); r.Code != 401 || r.Obj()["code"] != "unauthenticated" {
			t.Errorf("%s: %d %s, want 401", name, r.Code, r.Body)
		}
	}
	// Before verification, the ns check still answers 403 for both.
	if r := e.get("/ns", e.opGrant(map[string]any{"sub": "user:eve", "ns": []any{"main"}}).Encode()); r.Code != 403 {
		t.Fatalf("ns names a namespace: %d %s", r.Code, r.Body)
	}
}

// HTTP-69 (§7.4): the rows. { name, created, base?, frozen, purged }:
// created is that of the entry that created the namespace, the base's
// branch entry for a local branch and otherwise the chain's first; base is
// the namespace document's, without chain; frozen as §8.4, purged as §8.5.
// While authentication is disabled it answers everyone (§1).
func TestV084NamespacesRows(t *testing.T) {
	t.Parallel()
	var stored core.Options
	e := newEnv(t, withFileDB(t), func(o *core.Options) { stored = *o })

	e.mkNS("plain", map[string]any{})
	e.clock.Advance(time.Minute)
	e.mkNS("icy", map[string]any{})
	e.clock.Advance(time.Minute)
	expect(t, e.patchNS("icy", ops(op("add", "/frozen", true)), ""), 201)
	e.clock.Advance(time.Minute)
	e.mkNS("gone", map[string]any{})
	e.create("gone", "doc", map[string]any{"a": 1})
	e.clock.Advance(time.Minute)
	e.purgeDev("gone")
	e.clock.Advance(time.Minute)
	e.create("plain", "doc", map[string]any{"a": 1})
	at := e.nsHead("plain")
	e.clock.Advance(time.Minute)
	e.create("plain", "later", map[string]any{"a": 1})
	e.clock.Advance(time.Minute)
	branched := e.clock.Now()
	// A branch at an earlier ns_id, frozen from its genesis.
	expect(t, e.branch("plain", map[string]any{"name": "plain-b", "at": at, "patches": ops(op("add", "/frozen", true))}, "alice"), 201)
	e.clock.Advance(time.Minute)
	bbAt := e.nsHead("plain-b")
	expect(t, e.branch("plain-b", map[string]any{"name": "plain-bb"}, "alice"), 201)

	// Authentication is disabled: no credentials, and any are ignored.
	rows, next := e.nsPage("")
	if other, _ := e.nsPage("", "garbage"); !reflect.DeepEqual(other, rows) {
		t.Fatalf("with a bearer: %v, without: %v", other, rows)
	}
	stamp := func(tm time.Time) string { return tm.UTC().Format("2006-01-02T15:04:05.000Z") }
	want := []map[string]any{
		{"name": "gone", "created": stamp(t0.Add(3 * time.Minute)), "frozen": true, "purged": true},
		{"name": "icy", "created": stamp(t0.Add(time.Minute)), "frozen": true, "purged": false},
		{"name": "plain", "created": stamp(t0), "frozen": false, "purged": false},
		{"name": "plain-b", "created": stamp(branched), "base": map[string]any{"ns": "plain", "at": at}, "frozen": true, "purged": false},
		{"name": "plain-bb", "created": stamp(branched.Add(time.Minute)), "base": map[string]any{"ns": "plain-b", "at": bbAt}, "frozen": false, "purged": false},
	}
	if !reflect.DeepEqual(rows, want) || next != "" {
		t.Fatalf("rows\n %v\nwant\n %v\nnext %q", rows, want, next)
	}
	// The same from another server on the database, which has none of the
	// namespace documents in its configuration cache: the two ways base
	// and frozen are read agree.
	stored.BlobDir = t.TempDir()
	cold, err := core.Open(stored)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	page, err := cold.Namespaces(t.Context(), "", "", core.Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(page.Items, want) || page.Next != "" {
		t.Fatalf("rows of a cold server\n %v\nwant\n %v", page.Items, want)
	}
	if _, err := cold.Namespaces(t.Context(), "", "A", core.Credentials{}); err == nil {
		t.Fatal("the core accepts a prefix that is no namespace name")
	}
	for _, n := range []string{"icy", "plain", "plain-b", "plain-bb"} {
		expect(t, e.get("/ns/"+n+"/rev/"+e.nsHead(n)), 200)
	}
	if again, _ := e.nsPage(""); !reflect.DeepEqual(again, want) {
		t.Fatalf("rows with cached documents\n %v\nwant\n %v", again, want)
	}

	// created is the created of the base's branch entry, and base the
	// namespace document's.
	var entry map[string]any
	for _, x := range e.get("/ns/plain/rev/" + e.nsHead("plain") + "/log").Arr() {
		if m := x.(map[string]any); m["kind"] == "branch" && m["name"] == "plain-b" {
			entry = m
		}
	}
	if entry == nil || entry["created"] != rowOf(t, rows, "plain-b")["created"] {
		t.Fatalf("branch entry %v, row %v", entry, rowOf(t, rows, "plain-b"))
	}
	for _, n := range []string{"plain-b", "plain-bb"} {
		base := e.get("/ns/" + n + "/rev/" + e.nsHead(n)).Obj()["base"].(map[string]any)
		if got := rowOf(t, rows, n)["base"]; !reflect.DeepEqual(got, base) {
			t.Fatalf("%s: base %v, document's %v", n, got, base)
		}
	}

	// Unfreezing shows; a purged branch stays listed, with its base.
	expect(t, e.patchNS("icy", ops(op("replace", "/frozen", false)), ""), 201)
	e.purgeDev("plain-bb")
	rows, _ = e.nsPage("")
	if r := rowOf(t, rows, "icy"); r["frozen"] != false {
		t.Fatalf("unfrozen row %v", r)
	}
	if r := rowOf(t, rows, "plain-bb"); r["purged"] != true || r["frozen"] != true || !reflect.DeepEqual(r["base"], want[4]["base"]) || r["created"] != want[4]["created"] {
		t.Fatalf("purged branch row %v", r)
	}
	if got := rowNames(rows); !reflect.DeepEqual(got, []string{"gone", "icy", "plain", "plain-b", "plain-bb"}) {
		t.Fatalf("names %v", got)
	}
}
