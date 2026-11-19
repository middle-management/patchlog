package catalog_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// Tests for clauses of v0.86 the catalog service and its tree service
// already met: CONFORMANCE Tree 146, 147 and 149, and Access 85.

// v86Config appends ops to ns's namespace document and waits for the
// service.
func (w *world) v86Config(ns string, ops ...any) {
	w.t.Helper()
	ctx := context.Background()
	c := w.s.Client(w.t, client.WithBearer(w.opsKey.Grant(w.t, w.s.Now(), "user:ops", []string{ns}, []string{"read", "config"})))
	must(c.PatchConfig(ctx, ns, must(c.NSHead(ctx, ns)).Config, ops))
	w.caughtUp()
}

// v86Refused checks that r hands out nothing.
func v86Refused(t *testing.T, what string, r resp, statuses ...int) {
	t.Helper()
	ok := false
	for _, s := range statuses {
		ok = ok || r.status == s
	}
	if !ok || r.body["grant"] != nil || r.body["keys"] != nil || r.body["items"] != nil || r.body["children"] != nil || r.body["prefixes"] != nil {
		t.Errorf("%s: %d %v, want %v with no grant, no key and nothing listed", what, r.status, r.body, statuses)
	}
}

// TestV086ClaimsFromTheCatalogsKeysAlone (CONFORMANCE Tree 146 and 149;
// SERVICES §B.11.6 Whose claims, SVC-58: "A catalog service takes the
// caller's sub and groups from the base grant as the catalog namespace's
// keys verify it, so no content namespace's key asserts them for the
// catalog. A base grant that doesn't verify there is answered as the
// catalog namespace would answer it"; §B.11.5 Listing URLs: "A gs other
// than all takes its subjects as §B.11.6 Whose claims says"). A second
// identity provider's key is listed in matches alone, where it may
// assert any group. Its grant, naming the catalog and matches, asserts
// catalog-admins, or match-desk, to which the catalog's $access gives
// desk on season: POST /grants for a move or an item of matches and POST
// /read-grants are 401, as cat answers a key it doesn't list, with no
// grant and no key; a listing and the tree service's exchange show no
// item through those groups, and give no cookie.
func TestV086ClaimsFromTheCatalogsKeysAlone(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.startEdge()
	other := clienttest.NewKey("idp-content")
	w.v86Config("matches", map[string]any{"op": "add", "path": "/keys/-", "value": other.Entry("read")})
	for _, group := range []string{"catalog-admins", "match-desk"} {
		tok := other.Grant(t, w.s.Now(), "user:mallory", []string{"cat", "matches"}, []string{"read"}, map[string]any{"groups": toAny(group)})
		// The grant is good in matches, whose key signed it.
		if _, err := w.core(tok).Head(context.Background(), "matches", "derby"); err != nil {
			t.Fatalf("group %s: the grant doesn't read matches at the origin: %v", group, err)
		}
		what := "asserting " + group + " through a key of matches alone: "
		v86Refused(t, what+"a move", w.do("POST", "/grants", tok, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("derbies")}), 401)
		for _, want := range []string{"read", "append"} {
			v86Refused(t, what+"an item of matches, want "+want, w.do("POST", "/grants", tok, map[string]any{"item": "/r/matches/derby", "want": toAny(want)}), 401)
		}
		v86Refused(t, what+"POST /read-grants", w.do("POST", "/read-grants", tok, map[string]any{"items": toAny("/r/matches/derby")}), 401)
		// Tree 149: no item shown through the groups it asserts.
		v86Refused(t, what+"a listing", w.do("GET", "/cat/children?of=season", tok, nil), 401, 403)
		r, cks := w.exchange(tok, nil, "")
		v86Refused(t, what+"the tree service's exchange", r, 401, 403)
		if len(cks) != 0 {
			t.Errorf("%sthe exchange set %d cookies", what, len(cks))
		}
	}
	// The same claims through the catalog's own identity provider count.
	if r, _ := w.follow("/cat/children?of=season", w.caller("user:bob", "match-desk")); r.status != 200 || !strings.Contains(childNames(r.body), "matches.derby") {
		t.Errorf("match-desk through the catalog's identity provider: %d %v", r.status, r.body)
	}
}

// v86Failing answers requests under a path prefix with a status, once
// set, and passes the rest on.
type v86Failing struct {
	mu     sync.Mutex
	prefix string
	status int
}

func (f *v86Failing) set(prefix string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prefix, f.status = prefix, status
}

func (f *v86Failing) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	p, st := f.prefix, f.status
	f.mu.Unlock()
	if st == 0 || r.URL.Path != p && !strings.HasPrefix(r.URL.Path, p+"/") {
		return transport.RoundTrip(r)
	}
	return &http.Response{StatusCode: st, Header: http.Header{"Content-Type": {"application/json"}}, Request: r,
		Body: io.NopCloser(strings.NewReader(`{"code":"injected","message":"injected"}`))}, nil
}

// TestV086CallersGrantChainUnread (CONFORMANCE Tree 147; SERVICES §B.11.4
// The caller's grant, SVC-57: "where that turns on a requireAt chain the
// service can't read, they answer 502 or 503 as §C.4 gives them"). The
// caller's grant carries the role reader, which lists no verb in the
// catalog namespace, so it allows read nowhere there; in matches, where
// reader lists read, its key has a requireAt, whose chain the service
// can't read. Whether the grant reads anywhere can't be told: POST
// /read-grants and a read want are 503 behind while the cause is
// transient, else 502 upstream, never the caller's-grant 403. With the
// chain read, the grant is judged as usual.
//
// The key's requireAt names a namespace of its own, gate, where the
// scenario's names the catalog: a catalog the service can't read it
// can't follow either, and answers nothing from.
func TestV086CallersGrantChainUnread(t *testing.T) {
	t.Parallel()
	fail := &v86Failing{}
	w := setup(t)
	ctx := context.Background()
	// The service's own grant reads gate, as it must to check at.
	w.svcClient = w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches", "gate"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})), client.WithHTTPClient(&http.Client{Transport: fail}))
	kq := clienttest.NewKey("gated")
	must(w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, "gate"))).CreateNamespace(ctx, "gate",
		map[string]any{"read": "grant", "keys": []any{w.opsKey.Entry("*")}}))
	w.seed()
	w.start()
	w.caughtUp()
	gated := kq.Entry("read")
	gated["requireAt"], gated["maxTtl"] = "gate", "PT15M"
	w.v86Config("matches", map[string]any{"op": "add", "path": "/keys/-", "value": gated})
	w.v86Config("cat", map[string]any{"op": "add", "path": "/keys/-", "value": kq.Entry("read")})
	gateHead := must(w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"gate"}, []string{"read"}))).NSHead(ctx, "gate")).ID
	tok := kq.Grant(t, w.s.Now(), "user:fred", []string{"cat", "matches"}, []string{"read"}, map[string]any{
		"groups": toAny("fan-club"), "roles": toAny("reader"),
		"at":  map[string]any{"ns": "gate", "id": gateHead},
		"exp": w.s.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	items := map[string]any{"items": toAny("/r/matches/derby")}
	read := map[string]any{"item": "/r/matches/derby", "want": toAny("read")}
	if r := w.do("POST", "/read-grants", tok, items); r.status != 200 || entry(r, 0)["grant"] == nil {
		t.Fatalf("with the chain read, POST /read-grants: %d %v, want it judged as usual", r.status, r.body)
	}
	if r := w.do("POST", "/grants", tok, read); r.status != 200 || r.body["grant"] == nil {
		t.Fatalf("with the chain read, a read want: %d %v, want it judged as usual", r.status, r.body)
	}
	for _, c := range []struct {
		upstream, status int
		code             string
	}{{503, 503, "behind"}, {403, 502, "upstream"}} {
		fail.set("/ns/gate", c.upstream)
		w.svc.Tree().Checker().Invalidate()
		for what, r := range map[string]resp{"POST /read-grants": w.do("POST", "/read-grants", tok, items), "a read want": w.do("POST", "/grants", tok, read)} {
			if r.status != c.status || r.body["code"] != c.code || r.body["items"] != nil || r.body["grant"] != nil {
				t.Errorf("gate answering the service %d, %s: %d %v, want %d %s, never the caller's-grant 403", c.upstream, what, r.status, r.body, c.status, c.code)
			}
			if c.status == 503 && r.header.Get("Retry-After") == "" {
				t.Errorf("gate answering the service %d, %s: no Retry-After", c.upstream, what)
			}
		}
	}
}

// TestV086OperatorGrantAtTheCatalogService (CONFORMANCE Access 85; SPEC
// §C.4 Operator grants, v0.86: "Any other request under one, at the
// origin or a service (§C.6), is 401, as for a key the namespace doesn't
// list"). An operator grant, for the catalog namespace or for "*", is
// 401 at POST /grants and POST /read-grants, at a listing of the private
// catalog and at the tree service's exchange, which sets no cookie: the
// services verify a grant by the namespace's keys alone.
func TestV086OperatorGrantAtTheCatalogService(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.startEdge()
	for what, tok := range map[string]string{
		"an operator grant for the catalog": w.s.OperatorGrant(t, "cat"),
		"one that reads it": clienttest.Mint(t, w.s.OperatorKey, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"cat", "matches"},
			"can": []any{"read"}, "groups": []any{"catalog-admins"}, "exp": w.s.Now().Add(time.Hour).Format(time.RFC3339)}),
		"one for *": clienttest.Mint(t, w.s.OperatorKey, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"*"},
			"can": []any{"read"}, "exp": w.s.Now().Add(time.Hour).Format(time.RFC3339)}),
	} {
		v86Refused(t, what+": a read want", w.do("POST", "/grants", tok, map[string]any{"item": "/r/matches/derby", "want": toAny("read")}), 401)
		v86Refused(t, what+": a move", w.do("POST", "/grants", tok, map[string]any{"node": "matches.derby", "want": toAny("move"), "to": toAny("derbies")}), 401)
		v86Refused(t, what+": POST /read-grants", w.do("POST", "/read-grants", tok, map[string]any{"items": toAny("/r/matches/derby")}), 401)
		v86Refused(t, what+": a listing", w.do("GET", "/cat/children?of=season", tok, nil), 401)
		r, cks := w.exchange(tok, nil, "")
		v86Refused(t, what+": the tree service's exchange", r, 401)
		if len(cks) != 0 || r.header.Get("Set-Cookie") != "" {
			t.Errorf("%s: the exchange set a cookie", what)
		}
	}
}
