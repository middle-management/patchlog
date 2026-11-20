package index_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// Tests for clauses of v0.86 the index already met: scenarios Tree 144
// and 148, and Access 85.

// TestV086CookiesToldApartByExp (CONFORMANCE Tree 144; SERVICES §A.4 view,
// SPEC §C.5.2 Answer: a cookie lasts until its grant's exp "less any
// whole seconds a minter MAY take off so that cookies for one prefix that
// it must tell apart differ in exp"; §12.1 behind: "an exchange has no
// exp left for its cookie"). al and bo read docs whole through k1, under
// different read roles, with grants that expire at the same second: one
// marker, so one prefix, and cookies that differ in exp. al's role
// changes: only her cookie is 403. Where no whole second is left before
// the grant's exp, the exchange is 503 behind with Retry-After, and gives
// no cookie.
func TestV086CookiesToldApartByExp(t *testing.T) {
	t.Parallel()
	d := newV82Whole(t)
	d.patch(map[string]any{"op": "add", "path": "/roles/extra", "value": map[string]any{"can": []any{"read"}}})
	grant := func(sub, role string, exp time.Time) string {
		return d.k1.Grant(t, d.s.Now(), sub, []string{"docs"}, []string{"read"}, map[string]any{"roles": []any{role}, "exp": exp.Format(time.RFC3339)})
	}
	exp := d.s.Now().Truncate(time.Second).Add(10 * time.Minute)
	al, bo := grant("user:al", "extra", exp), grant("user:bo", "reader", exp)
	pa, alC := d.exchange(al)
	pb, boC := d.exchange(bo)
	if pa["docs"] != pb["docs"] {
		t.Fatalf("al and bo, through one key, have prefixes %v and %v", pa, pb)
	}
	cookie := func(cs []*http.Cookie) *http.Cookie {
		t.Helper()
		for _, c := range cs {
			if c.Path == pa["docs"] {
				return c
			}
		}
		t.Fatalf("no cookie for %s", pa["docs"])
		return nil
	}
	expOf := func(c *http.Cookie) time.Time {
		if !c.Expires.IsZero() {
			return c.Expires
		}
		return time.Unix(int64(c.MaxAge), 0)
	}
	a, b := cookie(alC), cookie(boC)
	if a.Value == b.Value || expOf(a).Equal(expOf(b)) {
		t.Fatalf("al's and bo's cookies for one prefix aren't told apart by exp: %v, %v", a, b)
	}
	if got, want := expOf(a).Sub(expOf(b)), time.Second; got != want {
		t.Errorf("the cookies' exps differ by %s, want a whole second taken off the later exchange's", got)
	}
	paths := v82Paths(pa)
	if ga, gb := v82Status(t, d.x, paths, alC), v82Status(t, d.x, paths, boC); ga != v82Reads || gb != v82Reads {
		t.Fatalf("under their cookies: al %s, bo %s", ga, gb)
	}
	// al's role changes.
	d.patch(map[string]any{"op": "replace", "path": "/roles/extra", "value": map[string]any{"can": []any{"read", "append"}}})
	if got := v82Status(t, d.x, paths, alC); got != v82Refuse {
		t.Errorf("al under her cookie once her role changed: %s, want 403", got)
	}
	if got := v82Status(t, d.x, paths, boC); got != v82Reads {
		t.Errorf("bo under his cookie once al's role changed: %s, want 200", got)
	}
	// No whole second left: a grant with one second to go, whose one
	// candidate exp another cookie of the prefix holds.
	short := d.s.Now().Truncate(time.Second).Add(time.Second)
	if _, c := d.exchange(grant("user:al", "extra", short)); len(c) == 0 {
		t.Fatalf("no cookie for the one second left")
	}
	r := p37Do(t, d.x, "POST", "/edge-grants", grant("user:bo", "reader", short), "", nil, "")
	if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") == "" || len(r.cookies) != 0 || r.header.Get("Set-Cookie") != "" {
		t.Errorf("an exchange with no second left for its cookie: %d %v, Retry-After %q, %d cookies; want 503 behind, Retry-After and no cookie",
			r.status, r.body, r.header.Get("Retry-After"), len(r.cookies))
	}
}

// TestV086OperatorGrantAtTheIndex (CONFORMANCE Access 85; SPEC §C.4
// Operator grants, v0.86: "Any other request under one, at the origin or
// a service (§C.6), is 401, as for a key the namespace doesn't list. …
// Requests that ignore any grant, such as public reads, … ignore it
// too"). An operator grant, naming the namespace or "*", is 401 at the
// index's exchange, with no cookie and no view, at GET /_refs and
// at a query on a private namespace; a public namespace's query ignores
// it. The index holds no operator key: it verifies a grant against the
// namespace's own keys alone.
func TestV086OperatorGrantAtTheIndex(t *testing.T) {
	t.Parallel()
	d := newV82Whole(t)
	wild := clienttest.Mint(t, d.s.OperatorKey, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"*"}, "can": []any{"read", "config"},
		"exp": d.s.Now().Add(time.Hour).Format(time.RFC3339)})
	named := clienttest.Mint(t, d.s.OperatorKey, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"docs"}, "can": []any{"read", "config"},
		"exp": d.s.Now().Add(time.Hour).Format(time.RFC3339)})
	grants := map[string]string{"an operator grant for the namespace": d.s.OperatorGrant(t, "docs"), "one that reads it": named, "one for *": wild}
	for what, tok := range grants {
		r := p37Do(t, d.x, "POST", "/edge-grants", tok, "", nil, "")
		if r.status != 401 || len(r.cookies) != 0 || r.header.Get("Set-Cookie") != "" || r.body["prefixes"] != nil || strings.Contains(r.body["message"].(string), "key:") {
			t.Errorf("%s, the exchange: %d %v, %d cookies; want 401 and no cookie", what, r.status, r.body, len(r.cookies))
		}
		if r := d.x.raw("/docs?q=word", tok); r.status != 401 {
			t.Errorf("%s, a query on private docs: %d %v, want 401", what, r.status, r.body)
		}
		if r := d.x.raw("/_refs?to=%2Fr%2Fdocs%2Fschema", tok); r.status != 401 {
			t.Errorf("%s, GET /_refs with nothing public followed: %d %v, want 401", what, r.status, r.body)
		}
	}
	// docs made public: its query ignores the grant, as it ignores any.
	d.patch(map[string]any{"op": "replace", "path": "/read", "value": "public"})
	anon := d.x.search("/docs?q=word", "")
	for what, tok := range grants {
		got := d.x.search("/docs?q=word", tok)
		if h, _ := got["hits"].([]any); len(h) != len(anon["hits"].([]any)) || len(h) == 0 {
			t.Errorf("%s, a query on public docs: %v, want what a request without a grant gets, %v", what, got, anon)
		}
		// /_refs with a public namespace followed shows its public hits,
		// the grant ignored like any that verifies nowhere.
		if r := d.x.raw("/_refs?to=%2Fr%2Fdocs%2Fschema", tok); r.status != 302 {
			t.Errorf("%s, GET /_refs once docs is public: %d %v, want the public answer's redirect", what, r.status, r.body)
		}
	}
}
