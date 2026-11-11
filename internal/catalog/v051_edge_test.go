package catalog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/tree"
)

// edgeKey is the catalog service's own edge-grant key in these tests.
var edgeKey = []byte("the catalog service's own edge-grant key")

// allCDN is the edge lifetime of a g/all listing: as long as a g/all
// cookie lives, 15 minutes, and a minute for edges' clocks.
const allCDN = "max-age=960"

// exchange posts to the service's /edge-grants: with token in
// Authorization, or with body (marshalled, as contentType), and returns
// the answer and its cookies.
func (w *world) exchange(token string, body any, contentType string) (resp, []*http.Cookie) {
	w.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(must(json.Marshal(body)))
	}
	req := must(http.NewRequest("POST", w.http.URL+"/edge-grants", rd))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res := must(noRedirect.Do(req))
	defer res.Body.Close()
	var m map[string]any
	_ = json.Unmarshal(must(io.ReadAll(res.Body)), &m)
	return resp{res.StatusCode, res.Header, m}, res.Cookies()
}

// withCookie reads path from the service with ck and no Authorization,
// plus the headers hdr.
func (w *world) withCookie(path string, ck *http.Cookie, hdr map[string]string) resp {
	w.t.Helper()
	h := map[string]string{"Cookie": ck.Name + "=" + ck.Value}
	for k, v := range hdr {
		h[k] = v
	}
	return w.doWith("GET", path, "", nil, h)
}

// prefixes is the prefixes of an exchange's answer.
func prefixes(r resp) string {
	var out []string
	for _, p := range r.body["prefixes"].([]any) {
		out = append(out, p.(string))
	}
	return strings.Join(out, ",")
}

// gsOf is the subject set of a listing URL /cat/g/{gs}/at/….
func gsOf(loc string) string {
	gs, _, _ := strings.Cut(strings.TrimPrefix(loc, "/cat/g/"), "/")
	return gs
}

// TestServiceEdgeGrants (§B.11.5, v0.51): the catalog service mints edge
// grants of its own for its listings. POST /edge-grants follows §C.5's
// issuance: a grant in Authorization or several in an application/json
// body, all or nothing, one cookie per prefix /{catalog}/g/{gs} of the
// subject set each resolves to, as listings resolve it, lasting until the
// grant's exp or 15 minutes. A read under one, without Authorization, is
// that subject set's at every at, and gets edge lifetimes only behind a
// verifying edge that checked it; the cookie covers no other subject
// set's URLs, and an origin's cookie covers none of the service's.
func TestServiceEdgeGrants(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	secret := []byte("edge secret shared with the service")
	w.edgeGrants = edge.NewCookies("catalog-cat", edgeKey)
	w.edge = must(edge.New(secret, "", ""))
	w.start()
	w.caughtUp()

	fan, fiona, li := w.caller("user:fred", "fan-club"), w.caller("user:fiona", "fan-club"), w.caller("user:li", "fan-club")
	withGrant, loc := w.follow("/cat/children?of=season", fan)
	_, locLi := w.follow("/cat/children?of=season", li)
	prefix := "/cat/g/" + gsOf(loc)

	// Exchange shapes.
	if r, cks := w.exchange("", nil, ""); r.status != 401 || len(cks) != 0 {
		t.Errorf("no grant: %d %v", r.status, cks)
	}
	r, cks := w.exchange(fan, nil, "")
	if r.status != 200 || prefixes(r) != prefix || len(cks) != 1 || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("one grant: %d %v %v", r.status, r.body, cks)
	}
	ck := cks[0]
	exp := must(time.Parse(time.RFC3339, r.body["exp"].(string)))
	if ck.Path != prefix || !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Name != edge.Name(prefix) ||
		exp.After(w.s.Now().Add(edge.MaxGrantTTL)) || exp.Before(w.s.Now().Add(edge.MaxGrantTTL-time.Minute)) {
		t.Errorf("cookie %+v, exp %v", ck, exp)
	}
	// Two grants of one subject set give one cookie; two subject sets two.
	if r, cks := w.exchange("", map[string]any{"grants": toAny(fan, fiona)}, "application/json"); r.status != 200 || prefixes(r) != prefix || len(cks) != 1 {
		t.Errorf("one subject set: %d %v", r.status, r.body)
	}
	if r, cks := w.exchange("", map[string]any{"grants": toAny(fan, li)}, "application/json; charset=utf-8"); r.status != 200 ||
		prefixes(r) != prefix+",/cat/g/"+gsOf(locLi) || len(cks) != 2 {
		t.Errorf("two subject sets: %d %v", r.status, r.body)
	}
	// A grant that lasts less than 15 minutes bounds its cookie.
	short := w.idp.Grant(t, w.s.Now(), "user:sam", []string{"cat"}, []string{}, map[string]any{"groups": toAny("fan-club"),
		"exp": w.s.Now().Add(90 * time.Second).Format(time.RFC3339)})
	if r, cks := w.exchange(short, nil, ""); r.status != 200 || len(cks) != 1 || cks[0].MaxAge > 90 || cks[0].MaxAge < 80 {
		t.Errorf("short grant: %d %v", r.status, cks)
	}
	for _, tc := range []struct {
		what        string
		token       string
		body        any
		contentType string
		status      int
	}{
		{"text/plain", "", map[string]any{"grants": toAny(fan)}, "text/plain", 415},
		{"a body and Authorization", fan, map[string]any{"grants": toAny(fan)}, "application/json", 400},
		{"no grants", "", map[string]any{"grants": []any{}}, "application/json", 400},
		{"another member", "", map[string]any{"grants": toAny(fan), "x": 1}, "application/json", 400},
		{"a grant that isn't a string", "", map[string]any{"grants": []any{1}}, "application/json", 400},
		{"all or nothing", "", map[string]any{"grants": toAny(fan, "biscuit:nonsense")}, "application/json", 401},
		{"all or nothing, another namespace's grant", "", map[string]any{"grants": toAny(fan,
			w.idp.Grant(t, w.s.Now(), "user:x", []string{"matches"}, []string{}))}, "application/json", 403},
	} {
		if r, cks := w.exchange(tc.token, tc.body, tc.contentType); r.status != tc.status || len(cks) != 0 {
			t.Errorf("%s: %d %v %v", tc.what, r.status, r.body, cks)
		}
	}
	if r := w.do("GET", "/edge-grants", fan, nil); r.status != 405 {
		t.Errorf("GET /edge-grants: %d", r.status)
	}

	// Reads under the cookie: the subject set's listing, with no grant.
	r = w.withCookie(loc, ck, nil)
	if r.status != 200 || childNames(r.body) != childNames(withGrant.body) ||
		r.header.Get("Cache-Control") != "private, max-age=300" || r.header.Get("CDN-Cache-Control") != "no-store" {
		t.Fatalf("read under the cookie: %d %v %v", r.status, r.header, r.body)
	}
	// Behind a verifying edge that checked it: edge lifetimes. With the
	// grant in Authorization, or a prefix that doesn't cover the URL, none.
	verified := map[string]string{edge.DefaultHeader: string(secret), edge.DefaultPrefixHeader: prefix}
	if r := w.withCookie(loc, ck, verified); r.status != 200 || r.header.Get("CDN-Cache-Control") != "max-age=31536000" || r.header.Get("Surrogate-Control") != "" {
		t.Errorf("verified by the edge: %d %v", r.status, r.header)
	}
	if r := w.doWith("GET", loc, fan, nil, verified); r.status != 200 || r.header.Get("CDN-Cache-Control") != "no-store" {
		t.Errorf("verified headers with Authorization: %d %v", r.status, r.header)
	}
	if r := w.withCookie(loc, ck, map[string]string{edge.DefaultHeader: string(secret), edge.DefaultPrefixHeader: "/cat/g/all"}); r.status != 200 || r.header.Get("CDN-Cache-Control") != "no-store" {
		t.Errorf("a prefix that doesn't cover the URL: %d %v", r.status, r.header)
	}
	// At several ats: the at of the cookie's issue, kept; another at, which
	// redirects to the current one in the same URL space; the current.
	w.patch("matches", "derby", map[string]any{"op": "add", "path": "/x", "value": 1})
	w.caughtUp()
	if r := w.withCookie(loc, ck, nil); r.status != 200 {
		t.Errorf("the kept at under the cookie: %d %v", r.status, r.body)
	}
	_, cur := w.follow("/cat/children?of=season", fan)
	r = w.withCookie(strings.Replace(cur, "/at/"+gsAt(cur)+"/", "/at/"+w.svc.Tree().Checkpoint("cat")+"/", 1), ck, nil)
	if r.status != 302 || r.header.Get("Location") != cur || r.header.Get("CDN-Cache-Control") != "no-store" {
		t.Errorf("another at under the cookie: %d %v", r.status, r.header)
	}
	if r := w.withCookie(cur, ck, nil); r.status != 200 || cur == loc {
		t.Errorf("the current at under the cookie: %d %s", r.status, cur)
	}
	// The cookie covers its subject set's URLs only, not the head pointer,
	// another subject set's or g/all.
	for _, path := range []string{"/cat/children?of=season", locLi, strings.Replace(cur, prefix, "/cat/g/all", 1)} {
		if r := w.withCookie(path, ck, nil); r.status != 401 {
			t.Errorf("%s under the cookie: %d", path, r.status)
		}
	}
	// A cookie the service's key vouches for, for a subject set it never
	// minted one for, is refused: it doesn't know the subjects.
	unknown := w.edgeGrants.Issue(edge.Claims{Prefix: "/cat/g/" + ids.FromBytes(make([]byte, ids.Size)).String(), Exp: w.s.Now().Add(time.Minute).Unix()}, w.s.Now())
	if r := w.withCookie(strings.Replace(cur, prefix, unknown.Path, 1), unknown, nil); r.status != 401 {
		t.Errorf("an unknown subject set: %d %v", r.status, r.body)
	}
	// The origin's cookies never cover the service's URLs, and the
	// service's never cover the core's, even under the same key bytes.
	origin := edge.NewCookies(edge.DefaultKid, edgeKey)
	if r := w.withCookie(cur, origin.Issue(edge.Claims{Prefix: prefix, Exp: exp.Unix()}, w.s.Now()), nil); r.status != 401 {
		t.Errorf("an origin's cookie on the service: %d", r.status)
	}
	for _, path := range []string{"/r/matches/derby", "/ns/matches"} {
		req := must(http.NewRequest("GET", w.s.URL+path, nil))
		req.AddCookie(w.edgeGrants.Issue(edge.Claims{Prefix: path, Exp: exp.Unix()}, w.s.Now()))
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		res := must(noRedirect.Do(req))
		res.Body.Close()
		if res.StatusCode != 401 {
			t.Errorf("the service's cookies on the core's %s: %d", path, res.StatusCode)
		}
	}

	// The subjects behind a gs outlast a restart.
	w.stop()
	w.start()
	w.caughtUp()
	if r := w.withCookie(cur, ck, nil); r.status != 200 {
		t.Errorf("after a restart: %d %v", r.status, r.body)
	}

	// Withdrawing them (§C.5): 204 with an expired cookie per prefix.
	req := must(http.NewRequest("DELETE", w.http.URL+"/edge-grants?prefix="+prefix+"&prefix="+prefix+"&prefix=/cat/g/all", nil))
	res := must(noRedirect.Do(req))
	res.Body.Close()
	if gone := res.Cookies(); res.StatusCode != 204 || len(gone) != 2 || gone[0].Name != ck.Name || gone[0].MaxAge != -1 || gone[0].Path != prefix ||
		res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("withdraw: %d %v", res.StatusCode, res.Cookies())
	}
	for _, q := range []string{"", "?prefix=/r/matches", "?prefix=/cat/g/x", "?prefix=" + prefix + "/at", "?prefix=" + prefix + "&x=1"} {
		req := must(http.NewRequest("DELETE", w.http.URL+"/edge-grants"+q, nil))
		res := must(noRedirect.Do(req))
		res.Body.Close()
		if res.StatusCode != 400 || len(res.Cookies()) != 0 {
			t.Errorf("withdraw %q: %d", q, res.StatusCode)
		}
	}
}

// TestServiceEdgeGrantForAll (§B.11.5, v0.51): a reader with
// namespace-wide read on the catalog and every content namespace it
// trusts exchanges for a cookie bound to all, expiring with the earliest
// of those grants. It covers every later at, so once the catalog trusts
// another namespace the cookie wasn't checked against, a read at an at
// including it is 403, until the reader exchanges again. An edge can't
// tell the cookies apart, so while such a cookie is live no shared cache
// keeps a g/all listing at such an at.
func TestServiceEdgeGrantForAll(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	ctx := context.Background()
	op := w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, "teams")))
	must(op.CreateNamespace(ctx, "teams", map[string]any{"read": "grant", "keys": []any{w.opsKey.Entry("*")}}))
	w.svcClient = w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches", "teams"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	w.edgeGrants = edge.NewCookies("catalog-cat", edgeKey)
	w.edgeOwnKey = true
	secret := []byte("edge secret shared with the service")
	w.edge = must(edge.New(secret, "", ""))
	verified := map[string]string{edge.DefaultHeader: string(secret), edge.DefaultPrefixHeader: "/cat/g/all"}
	w.start()
	w.caughtUp()
	// The engine's clock stands still: a cookie issued at the very instant
	// the service came to trust a namespace counts as issued before it.
	w.s.Clock.Advance(time.Second)

	exp := w.s.Now().Add(2 * time.Minute)
	wide := w.opsKey.Grant(t, w.s.Now(), "user:nw", []string{"cat", "matches"}, []string{"read"}, map[string]any{"exp": exp.Format(time.RFC3339)})
	r, cks := w.exchange(wide, nil, "")
	if r.status != 200 || prefixes(r) != "/cat/g/all" || len(cks) != 1 {
		t.Fatalf("namespace-wide reader: %d %v", r.status, r.body)
	}
	all := cks[0]
	if got := must(time.Parse(time.RFC3339, r.body["exp"].(string))); got.After(exp) || got.Before(exp.Add(-2*time.Second)) {
		t.Errorf("exp %v, want the grant's %v", got, exp)
	}
	_, loc := w.follow("/cat/children?of=season", wide)
	if !strings.HasPrefix(loc, "/cat/g/all/at/") {
		t.Fatalf("listing %s", loc)
	}
	r = w.withCookie(loc, all, nil)
	if r.status != 200 || childNames(r.body) != "matches.derby,matches.shared,rumours" {
		t.Errorf("g/all under the cookie: %d %v", r.status, r.body)
	}
	if cc := r.header.Get("Cache-Control"); !strings.HasPrefix(cc, "private, max-age=") || cc == "private, max-age=300" {
		t.Errorf("g/all Cache-Control %q: no longer than the cookie", cc)
	}
	if r := w.withCookie(strings.Replace(loc, "children?of=season", "problems", 1), all, nil); r.status != 200 {
		t.Errorf("problems under the cookie: %d %v", r.status, r.body)
	}
	// Behind a verifying edge, edge lifetimes: every namespace was trusted
	// before any g/all cookie was issued.
	if r := w.withCookie(loc, all, verified); r.status != 200 || !strings.HasPrefix(r.header.Get("CDN-Cache-Control"), "max-age=") {
		t.Errorf("g/all behind the edge: %d %v", r.status, r.header)
	}

	// The catalog comes to trust teams, after the cookie's issue.
	w.s.Clock.Advance(time.Second)
	opc := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "cat")).Config
	must(opc.PatchConfig(ctx, "cat", cfg, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "teams"}}))
	w.caughtUp()
	waitFor(t, "teams to be followed", func() bool { return w.svc.Tree().Checkpoint("teams") != "" })
	cur := strings.Replace(loc, "/at/"+gsAt(loc)+"/", "/at/"+w.svc.Tree().At()+"/", 1)
	if r := w.withCookie(cur, all, nil); r.status != 403 || r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("an at including teams: %d %v", r.status, r.body)
	}
	if r := w.withCookie(strings.Replace(cur, "children?of=season", "problems", 1), all, nil); r.status != 403 {
		t.Errorf("problems at an at including teams: %d", r.status)
	}
	// The kept at from before teams doesn't include it.
	if r := w.withCookie(loc, all, nil); r.status != 200 {
		t.Errorf("the at before teams: %d %v", r.status, r.body)
	}
	// Exchanging again: the grant no longer reads every trusted namespace,
	// so its cookie is the subject set's; one that reads teams too gets
	// all again, which covers the current at.
	if r, _ := w.exchange(wide, nil, ""); r.status != 200 || prefixes(r) == "/cat/g/all" {
		t.Errorf("without teams: %d %v", r.status, r.body)
	}
	w.s.Clock.Advance(time.Second)
	wider := w.opsKey.Grant(t, w.s.Now(), "user:nw", []string{"cat", "matches", "teams"}, []string{"read"}, map[string]any{"exp": exp.Format(time.RFC3339)})
	r, cks = w.exchange(wider, nil, "")
	if r.status != 200 || prefixes(r) != "/cat/g/all" || len(cks) != 1 {
		t.Fatalf("with teams: %d %v", r.status, r.body)
	}
	if cks[0].Value == all.Value {
		t.Error("the new cookie is the old one's bytes")
	}
	_, now := w.follow("/cat/children?of=season", wider)
	if r := w.withCookie(now, cks[0], nil); r.status != 200 {
		t.Errorf("the current at after exchanging again: %d %v", r.status, r.body)
	}
	// The old cookie still can't read there.
	if r := w.withCookie(now, all, nil); r.status != 403 {
		t.Errorf("the old cookie at the current at: %d", r.status)
	}
	// An edge would serve what it holds to the old cookie too, so while
	// that is live nothing at an at including teams is kept at the edge,
	// for the new cookie or a grant; the at from before is.
	if r := w.withCookie(now, cks[0], verified); r.status != 200 || r.header.Get("CDN-Cache-Control") != "no-store" || r.header.Get("Surrogate-Control") != "no-store" {
		t.Errorf("an at including teams behind the edge: %d %v", r.status, r.header)
	}
	if r := w.withCookie(strings.Replace(now, "children?of=season", "problems", 1), cks[0], verified); r.status != 200 || r.header.Get("CDN-Cache-Control") != "no-store" {
		t.Errorf("problems at an at including teams behind the edge: %d %v", r.status, r.header)
	}
	if r := w.doWith("GET", now, wider, nil, verified); r.status != 200 || r.header.Get("CDN-Cache-Control") != "no-store" {
		t.Errorf("an at including teams with a grant: %d %v", r.status, r.header)
	}
	if r := w.withCookie(loc, all, verified); r.status != 200 || !strings.HasPrefix(r.header.Get("CDN-Cache-Control"), "max-age=") {
		t.Errorf("the at before teams behind the edge: %d %v", r.status, r.header)
	}
	// Once the old cookie has expired, at an edge's lagging clock too, a
	// g/all listing including teams is kept at the edge again.
	w.s.Clock.Advance(exp.Sub(w.s.Now()) + time.Minute + time.Second)
	later := w.opsKey.Grant(t, w.s.Now(), "user:nw", []string{"cat", "matches", "teams"}, []string{"read"}, map[string]any{"exp": w.s.Now().Add(time.Hour).Format(time.RFC3339)})
	r, cks = w.exchange(later, nil, "")
	if r.status != 200 || prefixes(r) != "/cat/g/all" || len(cks) != 1 {
		t.Fatalf("later: %d %v", r.status, r.body)
	}
	if r := w.withCookie(now, cks[0], verified); r.status != 200 || r.header.Get("CDN-Cache-Control") != allCDN {
		t.Errorf("an at including teams after the old cookie expired: %d %v", r.status, r.header)
	}
}

// TestServiceEdgeGrantForAllSharedKey (§B.11.5): with a key the service
// doesn't hold alone (a key file, which a restart or another instance
// shares), every g/all cookie with one exp is the same bytes whoever was
// issued it, so the service never takes its issue from its own record: a
// cookie counts as issued at its exp less 15 minutes. One issued before
// the catalog trusted a namespace stays refused at an at including it
// after a restart, even once a reader who reads that namespace is issued
// the same bytes; and the edge keeps no g/all listing including it for 15
// minutes, and a minute for edges' clocks.
func TestServiceEdgeGrantForAllSharedKey(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	ctx := context.Background()
	op := w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, "teams")))
	must(op.CreateNamespace(ctx, "teams", map[string]any{"read": "grant", "keys": []any{w.opsKey.Entry("*")}}))
	w.svcClient = w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches", "teams"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	w.edgeGrants = edge.NewCookies("catalog-cat", edgeKey)
	secret := []byte("edge secret shared with the service")
	w.edge = must(edge.New(secret, "", ""))
	verified := map[string]string{edge.DefaultHeader: string(secret), edge.DefaultPrefixHeader: "/cat/g/all"}
	w.start()
	w.caughtUp()
	// A new database records its start as when matches became trusted:
	// until 15 minutes later, a short cookie counts as issued before it.
	w.s.Clock.Advance(17 * time.Minute)

	exp := w.s.Now().Add(2 * time.Minute)
	a := w.opsKey.Grant(t, w.s.Now(), "user:a", []string{"cat", "matches"}, []string{"read"}, map[string]any{"exp": exp.Format(time.RFC3339)})
	r, cks := w.exchange(a, nil, "")
	if r.status != 200 || prefixes(r) != "/cat/g/all" || len(cks) != 1 {
		t.Fatalf("a: %d %v", r.status, r.body)
	}
	old := cks[0]
	_, loc := w.follow("/cat/children?of=season", a)
	if r := w.withCookie(loc, old, verified); r.status != 200 || !strings.HasPrefix(r.header.Get("CDN-Cache-Control"), "max-age=") {
		t.Errorf("g/all behind the edge: %d %v", r.status, r.header)
	}

	w.s.Clock.Advance(time.Second)
	opc := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	cfg := must(w.ops.NSHead(ctx, "cat")).Config
	must(opc.PatchConfig(ctx, "cat", cfg, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "teams"}}))
	w.caughtUp()
	waitFor(t, "teams to be followed", func() bool { return w.svc.Tree().Checkpoint("teams") != "" })
	w.s.Clock.Advance(time.Second)
	cur := strings.Replace(loc, "/at/"+gsAt(loc)+"/", "/at/"+w.svc.Tree().At()+"/", 1)
	if r := w.withCookie(cur, old, nil); r.status != 403 {
		t.Errorf("the old cookie at an at including teams: %d", r.status)
	}
	// A cookie lasting the full 15 minutes was issued after teams: it
	// reads there, though the edge keeps nothing there yet.
	long := w.opsKey.Grant(t, w.s.Now(), "user:c", []string{"cat", "matches", "teams"}, []string{"read"}, map[string]any{"exp": w.s.Now().Add(time.Hour).Format(time.RFC3339)})
	r, cks = w.exchange(long, nil, "")
	if r.status != 200 || prefixes(r) != "/cat/g/all" {
		t.Fatalf("c: %d %v", r.status, r.body)
	}
	if r := w.withCookie(cur, cks[0], verified); r.status != 200 || r.header.Get("CDN-Cache-Control") != "no-store" {
		t.Errorf("a full-length cookie at an at including teams: %d %v", r.status, r.header)
	}

	// After a restart, a reader of teams whose grant expires with a's is
	// issued the same bytes, which still don't read there.
	w.stop()
	w.start()
	w.caughtUp()
	b := w.opsKey.Grant(t, w.s.Now(), "user:b", []string{"cat", "matches", "teams"}, []string{"read"}, map[string]any{"exp": exp.Format(time.RFC3339)})
	r, cks = w.exchange(b, nil, "")
	if r.status != 200 || prefixes(r) != "/cat/g/all" || len(cks) != 1 {
		t.Fatalf("b: %d %v", r.status, r.body)
	}
	if cks[0].Value != old.Value {
		t.Errorf("b's cookie isn't a's bytes")
	}
	if r := w.withCookie(cur, old, nil); r.status != 403 {
		t.Errorf("the old cookie at an at including teams after a restart: %d %v", r.status, r.body)
	}

	// Once 15 minutes and a minute have passed since teams was trusted,
	// the edge keeps g/all listings including it.
	w.s.Clock.Advance(edge.MaxGrantTTL + time.Minute + time.Second)
	later := w.opsKey.Grant(t, w.s.Now(), "user:c", []string{"cat", "matches", "teams"}, []string{"read"}, map[string]any{"exp": w.s.Now().Add(time.Hour).Format(time.RFC3339)})
	r, cks = w.exchange(later, nil, "")
	if r.status != 200 || prefixes(r) != "/cat/g/all" {
		t.Fatalf("later: %d %v", r.status, r.body)
	}
	_, now := w.follow("/cat/children?of=season", later)
	if r := w.withCookie(now, cks[0], verified); r.status != 200 || r.header.Get("CDN-Cache-Control") != allCDN {
		t.Errorf("an at including teams 16 minutes on: %d %v", r.status, r.header)
	}
}

// TestServiceEdgeGrantForAllUntrust (§B.11.5): every g/all cookie unlocks
// every g/all listing an edge holds, so when the catalog stops trusting a
// namespace, which a g/all cookie issued from then on isn't checked
// against, the service purges ns:{catalog}, the tag of every listing of
// the catalog; not ns:{ns}, which would evict all that every service
// caches of the namespace. Should that purge be lost, a g/all listing lives
// at the edge no longer than a g/all cookie, and a minute for edges'
// clocks; the service itself refuses the new cookie there.
func TestServiceEdgeGrantForAllUntrust(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	ctx := context.Background()
	op := w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, "teams")))
	must(op.CreateNamespace(ctx, "teams", map[string]any{"read": "grant", "keys": []any{w.opsKey.Entry("*")}}))
	w.svcClient = w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches", "teams"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	w.edgeGrants = edge.NewCookies("catalog-cat", edgeKey)
	w.edgeOwnKey = true
	secret := []byte("edge secret shared with the service")
	w.edge = must(edge.New(secret, "", ""))
	verified := map[string]string{edge.DefaultHeader: string(secret), edge.DefaultPrefixHeader: "/cat/g/all"}
	w.start()
	w.caughtUp()
	w.s.Clock.Advance(time.Second)

	wide := w.opsKey.Grant(t, w.s.Now(), "user:nw", []string{"cat", "matches"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(time.Hour).Format(time.RFC3339)})
	r, cks := w.exchange(wide, nil, "")
	if r.status != 200 || prefixes(r) != "/cat/g/all" || len(cks) != 1 {
		t.Fatalf("namespace-wide reader: %d %v", r.status, r.body)
	}
	_, loc := w.follow("/cat/children?of=season", wide)
	if r := w.withCookie(loc, cks[0], verified); r.status != 200 || r.header.Get("CDN-Cache-Control") != allCDN ||
		!slices.Contains(strings.Split(r.header.Get("Cache-Tag"), ","), "ns:cat") {
		t.Errorf("g/all behind the edge: %d %v", r.status, r.header)
	}
	if w.purged("ns:cat") {
		t.Fatal("ns:cat purged before the catalog stopped trusting matches")
	}

	// The catalog trusts teams instead of matches.
	w.s.Clock.Advance(time.Second)
	opc := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "user:ops", []string{"cat"}, []string{"config"})))
	must(opc.PatchConfig(ctx, "cat", must(w.ops.NSHead(ctx, "cat")).Config,
		[]any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{"teams"}}}))
	waitFor(t, "teams to be followed", func() bool { return w.svc.Tree().Checkpoint("teams") != "" })
	waitFor(t, "the purge of ns:cat", func() bool { return w.purged("ns:cat") })
	if w.purged("ns:matches") || w.purged("ns:teams") {
		t.Error("a content namespace's tag purged")
	}
	// A reader with no read on matches now gets a g/all cookie, the same
	// name and path; the service refuses it at the at including matches.
	w.s.Clock.Advance(time.Second)
	narrow := w.opsKey.Grant(t, w.s.Now(), "user:x", []string{"cat", "teams"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(time.Hour).Format(time.RFC3339)})
	r, cks2 := w.exchange(narrow, nil, "")
	if r.status != 200 || prefixes(r) != "/cat/g/all" || len(cks2) != 1 || cks2[0].Name != cks[0].Name {
		t.Fatalf("a reader without matches: %d %v", r.status, r.body)
	}
	if r := w.withCookie(loc, cks2[0], verified); r.status != 403 {
		t.Errorf("the at including matches under the new cookie: %d %v", r.status, r.body)
	}
}

// TestServiceEdgeGrantExchangeRate (§C.5, §6.6, v0.52): once nothing is
// refused, an exchange draws one token, however many grants it carries,
// from the exchangeRate bucket of each distinct principal among them, and
// is 429 rate while any is empty, drawing none. A refused exchange draws
// nothing. The exchange takes no query parameters (§7).
func TestServiceEdgeGrantExchangeRate(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.edgeGrants = edge.NewCookies("catalog-cat", edgeKey)
	w.exchangeRate = tree.Rate{Rate: 1, Burst: 2}
	w.start()
	w.caughtUp()
	fan, fiona := w.caller("user:fred", "fan-club"), w.caller("user:fiona", "fan-club")

	for i := range 3 {
		if r, _ := w.exchange("", map[string]any{"grants": toAny(fan, "biscuit:nonsense")}, "application/json"); r.status != 401 {
			t.Fatalf("refused %d: %d", i, r.status)
		}
	}
	for i := range 2 {
		if r, cks := w.exchange(fan, nil, ""); r.status != 200 || len(cks) != 1 {
			t.Fatalf("fan %d: %d %v", i, r.status, r.body)
		}
	}
	r, cks := w.exchange(fan, nil, "")
	if r.status != 429 || r.body["code"] != "rate" || r.body["limit"] != "exchangeRate" || r.header.Get("Retry-After") != "1" ||
		r.header.Get("Cache-Control") != "no-store" || len(cks) != 0 {
		t.Errorf("fan's third: %d %v %v", r.status, r.header, r.body)
	}
	// Two grants of one principal draw one token; with an empty bucket
	// among them, none.
	if r, _ := w.exchange("", map[string]any{"grants": toAny(fiona, fiona)}, "application/json"); r.status != 200 {
		t.Errorf("fiona twice: %d %v", r.status, r.body)
	}
	if r, cks := w.exchange("", map[string]any{"grants": toAny(fiona, fan)}, "application/json"); r.status != 429 || len(cks) != 0 {
		t.Errorf("fiona and fan: %d %v", r.status, r.body)
	}
	if r, _ := w.exchange(fiona, nil, ""); r.status != 200 {
		t.Errorf("fiona's last token: %d %v", r.status, r.body)
	}
	if r, _ := w.exchange(fiona, nil, ""); r.status != 429 {
		t.Errorf("fiona, empty: %d %v", r.status, r.body)
	}
	w.s.Clock.Advance(time.Second)
	if r, _ := w.exchange(fan, nil, ""); r.status != 200 {
		t.Errorf("fan a second later: %d %v", r.status, r.body)
	}

	req := must(http.NewRequest("POST", w.http.URL+"/edge-grants?x=1", nil))
	req.Header.Set("Authorization", "Bearer "+fiona)
	res := must(noRedirect.Do(req))
	res.Body.Close()
	if res.StatusCode != 400 || len(res.Cookies()) != 0 || res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("a query parameter: %d", res.StatusCode)
	}
}

// gsAt is the at of a listing URL.
func gsAt(loc string) string {
	_, rest, _ := strings.Cut(loc, "/at/")
	at, _, _ := strings.Cut(rest, "/")
	return at
}

// TestServiceEdgeGrantsNotOffered: without edge grants of its own, or
// while the core's authentication is disabled (§1), the service's
// issuance is 404 not_offered (§C.5).
func TestServiceEdgeGrantsNotOffered(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	fan := w.caller("user:fred", "fan-club")
	if r, cks := w.exchange(fan, nil, ""); r.status != 404 || r.body["code"] != "not_offered" || len(cks) != 0 {
		t.Errorf("without edge grants: %d %v", r.status, r.body)
	}
	if r := w.do("DELETE", "/edge-grants?prefix=/cat/g/all", "", nil); r.status != 404 || r.body["code"] != "not_offered" {
		t.Errorf("withdraw without edge grants: %d %v", r.status, r.body)
	}
	w.stop()

	w.edgeGrants = edge.NewCookies("catalog-cat", edgeKey)
	w.svcClient = must(client.New(w.s.AuthProxy(t, "disabled"), client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat", "matches"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)}))))
	w.start()
	if r, cks := w.exchange(fan, nil, ""); r.status != 404 || r.body["code"] != "not_offered" || len(cks) != 0 {
		t.Errorf("authentication disabled: %d %v", r.status, r.body)
	}
	if r, _ := w.exchange("", map[string]any{"grants": toAny(fan)}, "text/plain"); r.status != 404 {
		t.Errorf("authentication disabled, before the body: %d %v", r.status, r.body)
	}
	if r := w.do("DELETE", "/edge-grants?prefix=/cat/g/all", "", nil); r.status != 204 {
		t.Errorf("withdraw with authentication disabled: %d %v", r.status, r.body)
	}
}
