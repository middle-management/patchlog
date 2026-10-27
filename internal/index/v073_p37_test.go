package index_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// p37World is pa and pb (read: grant) and pub (public), followed by one
// index that mints edge grants of its own behind a verifying edge. pa
// holds a and b, pb c, pub p; every document references /r/target/x.
type p37World struct {
	s             *clienttest.Server
	x             *svc
	admin, issuer clienttest.Key
	db            string
	rate          svcedge.Rate
}

func p37Setup(t *testing.T, rate svcedge.Rate) *p37World {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	nss := []string{"schemas", "pa", "pb", "pub"}
	for _, ns := range nss {
		doc := map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}
		if ns == "pub" || ns == "schemas" {
			doc["read"] = "public"
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	root := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", nss, []string{"read", "create", "append"})))
	sch := must(root.CreateDoc(ctx, "schemas", "page", pageSchema(true)))
	for ns, names := range map[string][]string{"pa": {"a", "b"}, "pb": {"c"}, "pub": {"p"}} {
		for _, n := range names {
			must(root.CreateDoc(ctx, ns, n, map[string]any{"$schema": "/r/schemas/page/rev/" + sch.ID, "related": []any{"/r/target/x"}}))
		}
	}
	w := &p37World{s: s, admin: admin, issuer: issuer, db: filepath.Join(t.TempDir(), "i.db"), rate: rate}
	w.x = w.start(t)
	return w
}

// start starts an index instance on w's database, minting with one key
// every instance holds.
func (w *p37World) start(t *testing.T) *svc {
	t.Helper()
	ev := must(edge.New([]byte("s3cret"), "", ""))
	x := startSvcWith(t, w.s.Client(t, client.WithBearer(w.admin.Grant(t, w.s.Now(), "svc:indexer", []string{"pa", "pb", "pub"}, []string{"read"}))),
		svcOpts{db: w.db, ns: []string{"pa", "pb", "pub"}, untyped: true, now: w.s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), w.rate, ev
		})
	for _, ns := range []string{"pa", "pb", "pub"} {
		x.caughtUp(ns)
	}
	return x
}

// p37Resp is an answer with its cookies.
type p37Resp struct {
	resp
	cookies []*http.Cookie
}

// do sends method path to x with token in Authorization (if set), body
// as application/json (if set), cookies, and the verifying edge's headers
// for prefix (if set).
func p37Do(t *testing.T, x *svc, method, path, token, body string, cookies []*http.Cookie, prefix string) p37Resp {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := must(http.NewRequest(method, x.http.URL+path, rd))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	if prefix != "" {
		req.Header.Set(edge.DefaultHeader, "s3cret")
		req.Header.Set(edge.DefaultPrefixHeader, prefix)
	}
	r := must(noFollow.Do(req))
	defer r.Body.Close()
	b := must(io.ReadAll(r.Body))
	out := p37Resp{resp: resp{status: r.StatusCode, header: r.Header}, cookies: r.Cookies()}
	if len(b) > 0 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(b, &out.body); err != nil {
			t.Fatalf("%s %s: %d %s", method, path, r.StatusCode, b)
		}
	}
	return out
}

// exchange exchanges token at x's POST /edge-grants and returns the
// prefixes, by kind (the namespace, or "_refs"), and the cookies.
func (w *p37World) exchange(t *testing.T, x *svc, token string) (map[string]string, []*http.Cookie) {
	t.Helper()
	r := p37Do(t, x, "POST", "/edge-grants", token, "", nil, "")
	if r.status != 200 || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("exchange: %d %v %v", r.status, r.body, r.header)
	}
	prefixes := map[string]string{}
	for _, p := range r.body["prefixes"].([]any) {
		segs := strings.Split(p.(string), "/")
		prefixes[segs[1]] = p.(string)
	}
	if len(r.cookies) != len(prefixes) {
		t.Fatalf("%d cookies for %v", len(r.cookies), prefixes)
	}
	for _, c := range r.cookies {
		if c.Name != edge.Name(c.Path) || !c.Secure || !c.HttpOnly || prefixes[strings.Split(c.Path, "/")[1]] != c.Path {
			t.Fatalf("cookie %+v for %v", c, prefixes)
		}
	}
	return prefixes, r.cookies
}

// follow follows redirects from path with cookies only, as a browser
// behind the edge does, and returns the 200 and the at URL it came from.
func p37Follow(t *testing.T, x *svc, path string, cookies []*http.Cookie, prefix string) (p37Resp, string) {
	t.Helper()
	for range 5 {
		r := p37Do(t, x, "GET", path, "", "", cookies, prefix)
		if r.status != 302 {
			return r, path
		}
		path = r.header.Get("Location")
	}
	t.Fatalf("%s: too many redirects", path)
	return p37Resp{}, ""
}

func p37Hits(body map[string]any) []string {
	var out []string
	for _, h := range body["hits"].([]any) {
		m := h.(map[string]any)
		ns, _ := m["ns"].(string)
		out = append(out, strings.TrimPrefix(ns+"/"+m["resource"].(string), "/"))
	}
	return out
}

// TestV073P37IndexEdgeGrants (IX-18, §A.4, §B.11.5, §C.5.2–§C.5.4): the
// index serves its gs URLs as §B.11.5 says. Its own POST /edge-grants
// exchanges a grant for cookies, minted with its key, for /{ns}/g/{gs} of
// each private namespace it follows that the grant names and
// /_refs/g/{gs} of the reader's subject set; a GET with only the cookie
// is authorised from it at the origin (the head pointer under the prefix
// and the at URLs), and behind a verifying edge gets edge lifetimes. A
// reader whose grant reads only some resources gets them filtered as
// under the grant. Neither grant nor cookie is 401, and so is the cookie
// at another gs, which it doesn't cover. DELETE /edge-grants withdraws.
func TestV073P37IndexEdgeGrants(t *testing.T) {
	t.Parallel()
	w := p37Setup(t, svcedge.DefaultExchangeRate)
	x := w.x
	amy := w.issuer.Grant(t, w.s.Now(), "user:amy", []string{"pa", "pb"}, []string{"read"})
	carl := w.issuer.Grant(t, w.s.Now(), "user:carl", []string{"pa"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})

	prefixes, cookies := w.exchange(t, x, amy)
	if len(prefixes) != 3 || prefixes["pa"] == "" || prefixes["pb"] == "" || prefixes["_refs"] == "" {
		t.Fatalf("amy's prefixes: %v", prefixes)
	}
	// The grant's own subject set is the cookie's.
	_, gs := path(prefixes["pa"])
	if r := x.raw("/pa?limit=5", amy); r.status != 302 || !strings.HasPrefix(r.header.Get("Location"), prefixes["pa"]+"/at/") {
		t.Fatalf("amy's pointer: %d %s (want under %s)", r.status, r.header.Get("Location"), prefixes["pa"])
	}
	r, at := p37Follow(t, x, prefixes["pa"]+"?limit=5", cookies, "")
	if r.status != 200 || strings.Join(p37Hits(r.body), ",") != "a,b" || r.header.Get("CDN-Cache-Control") != "no-store" {
		t.Fatalf("pa under the cookie, without the edge: %d %v %v", r.status, r.body, r.header)
	}
	// Behind the verifying edge, which checked the cookie: edge lifetimes.
	if r := p37Do(t, x, "GET", at, "", "", cookies, prefixes["pa"]); r.status != 200 || r.header.Get("CDN-Cache-Control") != "max-age=31536000" {
		t.Errorf("pa under the cookie, behind the edge: %d %v", r.status, r.header)
	}
	if r, _ := p37Follow(t, x, prefixes["_refs"]+"?to="+url.QueryEscape("/r/target/x"), cookies, ""); r.status != 200 || strings.Join(p37Hits(r.body), ",") != "pa/a,pa/b,pb/c,pub/p" {
		t.Errorf("/_refs under the cookie: %d %v", r.status, r.body)
	}
	// Neither grant nor cookie, or a cookie that doesn't cover the URL.
	_, refsGS := path(prefixes["_refs"])
	other := strings.Replace(at, gs, refsGS, 1)
	for _, c := range [][]*http.Cookie{nil, cookies} {
		if r := p37Do(t, x, "GET", other, "", "", c, ""); r.status != 401 {
			t.Errorf("another gs's at URL with %d cookies: %d %v", len(c), r.status, r.body)
		}
	}
	if r := p37Do(t, x, "GET", at, "", "", nil, ""); r.status != 401 {
		t.Errorf("no grant, no cookie: %d %v", r.status, r.body)
	}

	// Per resource: carl reads only a of pa, under his cookie too.
	cp, cc := w.exchange(t, x, carl)
	if len(cp) != 2 || cp["pa"] == "" || cp["pa"] == prefixes["pa"] {
		t.Fatalf("carl's prefixes: %v", cp)
	}
	if r, _ := p37Follow(t, x, cp["pa"]+"?limit=5", cc, ""); r.status != 200 || strings.Join(p37Hits(r.body), ",") != "a" {
		t.Errorf("pa under carl's cookie: %d %v", r.status, r.body)
	}
	if r, _ := p37Follow(t, x, cp["_refs"]+"?to="+url.QueryEscape("/r/target/x"), cc, ""); r.status != 200 || strings.Join(p37Hits(r.body), ",") != "pa/a,pub/p" {
		t.Errorf("/_refs under carl's cookie: %d %v", r.status, r.body)
	}
	// A restarted instance on the same database knows the subject sets.
	x.stop()
	x2 := w.start(t)
	if r, _ := p37Follow(t, x2, cp["pa"]+"?limit=5", cc, ""); r.status != 200 || strings.Join(p37Hits(r.body), ",") != "a" {
		t.Errorf("pa under carl's cookie after a restart: %d %v", r.status, r.body)
	}

	// Withdrawal, and the exchange's refusals.
	wd := p37Do(t, x2, "DELETE", "/edge-grants?prefix="+url.QueryEscape(prefixes["pa"])+"&prefix="+url.QueryEscape(prefixes["pa"]), "", "", nil, "")
	if wd.status != 204 || len(wd.cookies) != 1 || wd.cookies[0].Name != edge.Name(prefixes["pa"]) || wd.cookies[0].MaxAge >= 0 {
		t.Errorf("withdrawal: %d %+v", wd.status, wd.cookies)
	}
	if r := p37Do(t, x2, "DELETE", "/edge-grants?prefix=/r/pa", "", "", nil, ""); r.status != 400 {
		t.Errorf("withdrawing a core prefix: %d", r.status)
	}
	req := must(http.NewRequest("POST", x2.http.URL+"/edge-grants", strings.NewReader(`{"grants":["`+amy+`"]}`)))
	req.Header.Set("Content-Type", "text/plain")
	if res := must(noFollow.Do(req)); res.StatusCode != 415 {
		t.Errorf("a text/plain body: %d", res.StatusCode)
	}
	if r := p37Do(t, x2, "POST", "/edge-grants", "", "", nil, ""); r.status != 401 {
		t.Errorf("neither grant nor body: %d", r.status)
	}
	if r := p37Do(t, x2, "POST", "/edge-grants", "", `{"grants":["`+amy+`","`+carl+`"]}`, nil, ""); r.status != 200 || len(r.cookies) != 5 {
		t.Errorf("two grants in the body: %d %v (%d cookies)", r.status, r.body, len(r.cookies))
	}
	pubOnly := w.issuer.Grant(t, w.s.Now(), "user:dee", []string{"pub"}, []string{"read"})
	if r := p37Do(t, x2, "POST", "/edge-grants", pubOnly, "", nil, ""); r.status != 403 {
		t.Errorf("a grant naming no private namespace: %d %v", r.status, r.body)
	}
	other37 := clienttest.NewKey("stranger").Grant(t, w.s.Now(), "user:eve", []string{"pa"}, []string{"read"})
	if r := p37Do(t, x2, "POST", "/edge-grants", "", `{"grants":["`+amy+`","`+other37+`"]}`, nil, ""); r.status != 401 || len(r.cookies) != 0 {
		t.Errorf("all or nothing, one grant unverifiable: %d %v", r.status, r.body)
	}
}

// path splits an index prefix /{ns}/g/{gs}.
func path(p string) (ns, gs string) {
	segs := strings.Split(p, "/")
	return segs[1], segs[3]
}

// TestV073P37IndexExchangeRateShared (IX-18, §B.11.5, §6.6): the index's
// exchangeRate buckets are shared by its instances through its database,
// and an exchange that finds a bucket empty is 429 limit exchangeRate
// with Retry-After. Without EdgeGrants the endpoint is 404 not_offered.
func TestV073P37IndexExchangeRateShared(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rate := svcedge.Rate{Rate: 0.001, Burst: 1}
	w := p37Setup(t, rate)
	sdb := must(sql.Open("sqlite", sqlitedsn.DSN(w.db, "_pragma=busy_timeout(10000)")))
	t.Cleanup(func() { sdb.Close() })
	other := must(svcedge.NewStore(ctx, sdb))
	amy := w.issuer.Grant(t, w.s.Now(), "user:amy", []string{"pa"}, []string{"read"})
	w.exchange(t, w.x, amy)
	if wait := must(other.Draw(ctx, w.s.Now(), rate, []string{"user:amy\x00issuer"})); wait == 0 {
		t.Fatal("another instance drew from the bucket the service drained")
	}
	must(other.Draw(ctx, w.s.Now(), rate, []string{"user:bo\x00issuer"}))
	bo := w.issuer.Grant(t, w.s.Now(), "user:bo", []string{"pa"}, []string{"read"})
	r := p37Do(t, w.x, "POST", "/edge-grants", bo, "", nil, "")
	if r.status != 429 || r.body["limit"] != "exchangeRate" || r.header.Get("Retry-After") == "" || len(r.cookies) != 0 {
		t.Errorf("bo's exchange after another instance drained his bucket: %d %v", r.status, r.body)
	}

	plain := startSvc(t, w.s.Client(t, client.WithBearer(w.admin.Grant(t, w.s.Now(), "svc:indexer", []string{"pa"}, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "p.db"), ns: []string{"pa"}, untyped: true, now: w.s.Now})
	for _, m := range []string{"POST", "DELETE"} {
		if r := p37Do(t, plain, m, "/edge-grants?prefix=/pa/g/x", amy, "", nil, ""); r.status != 404 || r.body["code"] != "not_offered" {
			t.Errorf("%s without edge grants: %d %v", m, r.status, r.body)
		}
	}
	if !slices.Contains([]int{404}, p37Do(t, plain, "GET", "/edge-grants", "", "", nil, "").status) {
		t.Error("GET /edge-grants is a query of a namespace the service doesn't follow")
	}
}

// p37Kids is the kid of each hit's sealed entry, by resource.
func p37Kids(t *testing.T, body []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, h := range decodeJSON(t, body)["hits"].([]any) {
		h := h.(map[string]any)
		name := h["resource"].(string)
		if ns, _ := h["ns"].(string); ns != "" {
			name = ns + "/" + name
		}
		jwe, _ := h["sealed"].(string)
		if jwe == "" {
			out[name] = ""
			continue
		}
		out[name] = must(seal.ParseHeader(jwe)).Kid
	}
	return out
}

// TestV073P37SealedEpochs (ENC-32, IX-25, §E.2.6, §E.2.2): hits are sealed
// under the epoch their document's revision is served under, the kid of
// the sealed document the service fetched, not the epoch current when the
// result is sealed. After a rotation a reader of the namespace whole gets
// a result whose hits all come from epoch 1 sealed whole under sec#1, one
// mixing revisions of epochs 1 and 2 per entry, each hit under its own
// epoch's K_r, and counts over those 400 (aggregates are served only
// sealed whole); a reader of some resources gets each hit under its
// epoch; /_refs seals each hit under its epoch. A rewritten document
// moves to the epoch it was written under.
func TestV073P37SealedEpochs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"sec", "schemas"} {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if ns == "sec" {
			doc["read"] = "grant"
			doc["encryption"] = map[string]any{"level": "sealed"}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec", "schemas"}, []string{"read", "create", "append", "config"})), client.WithKeys(client.NewKeys(nil)))
	sch := must(w.CreateDoc(ctx, "schemas", "item", pageSchemaWith(map[string]any{
		"title": map[string]any{"type": "string", "x-index": "text"}, "tag": map[string]any{"type": "string", "x-index": "facet"}})))
	ref := "/r/schemas/item/rev/" + sch.ID
	for _, n := range []string{"a", "b"} {
		must(createNonced(w, "sec", n, map[string]any{"$schema": ref, "title": "old " + n, "tag": "t", "related": []any{"/r/target/x"}}))
	}
	keys1 := epochKeys(t, w, "sec")
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"}, map[string]any{"enc": jwk})),
		client.WithKeys(client.NewKeys(priv)))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, now: s.Now}, func(o *indexOpts) { o.Recipient = priv })
	x.caughtUp("sec")
	must(s.Engine.RotateEpoch(ctx, "sec", "system:rotate"))
	must(createNonced(w, "sec", "c", map[string]any{"$schema": ref, "title": "new c", "tag": "t", "related": []any{"/r/target/x"}}))
	x.caughtUp("sec")
	keys2 := epochKeys(t, w, "sec")
	keyOf := func(kid string) []byte {
		if b := keys1(kid); b != nil {
			return b
		}
		return keys2(kid)
	}
	whole := k.Grant(t, s.Now(), "user:r", []string{"sec"}, []string{"read"})

	// Only epoch-1 revisions: sealed whole, under sec#1.
	f := x.fetch("/sec?q=old", whole)
	if h := must(seal.ParseHeader(string(f.body))); f.header.Get("Content-Type") != seal.ContentType || h.Kid != "sec#1" {
		t.Fatalf("a result of epoch-1 revisions: %s %s", f.header.Get("Content-Type"), h.Kid)
	}
	if got := strings.Join(resources(decodeJSON(t, must(derived.OpenView(string(f.body), keyOf, derived.View{NS: "sec", Target: f.path})))), ","); got != "a,b" {
		t.Errorf("epoch-1 hits %s", got)
	}
	// Mixed epochs: per entry, each hit under its revision's epoch.
	f = x.fetch("/sec?facet%5B%2Ftag%5D=t", whole)
	if f.header.Get("Content-Type") != "application/json" {
		t.Fatalf("a result mixing epochs: %s", f.header.Get("Content-Type"))
	}
	if got := p37Kids(t, f.body); fmt.Sprint(got) != "map[a:sec#1 b:sec#1 c:sec#2]" {
		t.Errorf("kids %v", got)
	}
	for _, h := range decodeJSON(t, f.body)["hits"].([]any) {
		h := h.(map[string]any)
		name := h["resource"].(string)
		if _, err := derived.OpenItem(h["sealed"].(string), derived.ItemKey(keyOf, "sec", name), derived.View{NS: "sec", Target: f.path}, "sec", name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if r := x.raw("/sec?facet%5B%2Ftag%5D=t&counts=/tag", whole); r.status != 302 {
		t.Fatalf("counts pointer: %d %v", r.status, r.body)
	} else if r := x.raw(r.header.Get("Location"), whole); r.status != 400 || r.body["code"] != "bad_input" {
		t.Errorf("counts over epochs 1 and 2: %d %v", r.status, r.body)
	}
	// A reader of some resources: per entry, under each hit's epoch.
	some := k.Grant(t, s.Now(), "user:li", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"a", "c"}}}}})
	if got := p37Kids(t, x.fetch("/sec?facet%5B%2Ftag%5D=t", some).body); fmt.Sprint(got) != "map[a:sec#1 c:sec#2]" {
		t.Errorf("per-resource reader's kids %v", got)
	}
	// Across namespaces, per entry.
	if got := p37Kids(t, x.fetch("/_refs?to="+url.QueryEscape("/r/target/x"), whole).body); fmt.Sprint(got) != "map[sec/a:sec#1 sec/b:sec#1 sec/c:sec#2]" {
		t.Errorf("/_refs kids %v", got)
	}
	// a rewritten after the rotation is served under epoch 2.
	h := must(w.Head(ctx, "sec", "a"))
	must(w.Append(ctx, "sec", "a", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "new a"},
		map[string]any{"op": "replace", "path": "/$nonce", "value": seal.NewNonce()}}))
	x.caughtUp("sec")
	f = x.fetch("/sec?q=new", whole)
	if h := must(seal.ParseHeader(string(f.body))); h.Kid != "sec#2" {
		t.Errorf("a result of epoch-2 revisions: %s", h.Kid)
	}
}

// TestV073P37E2EEpochs (ENC-32, IX-25, §E.2.6, §E.3.1): at E3 a hit is
// sealed under the epoch of the sealed op its document comes from.
func TestV073P37E2EEpochs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	admin := clienttest.NewKey("admin")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"read": "public", "keys": []any{admin.Entry("*")},
		"encryption": map[string]any{"level": "e2e"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "schemas"))).CreateNamespace(ctx, "schemas", map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}))
	adminJWK, adminPriv, _ := seal.GenerateRecipient()
	idxJWK, idxPriv, _ := seal.GenerateRecipient()
	ac := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:admin", []string{"e", "schemas"}, []string{"read", "create", "append", "config"}, map[string]any{"enc": adminJWK})))
	ad := ac.E2E(adminPriv)
	sch := must(ac.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}}}))
	must(ad.InitKeyring(ctx, "e", idxPriv.PublicKey()))
	must(ad.CreateDocSealed(ctx, "e", "a", map[string]any{"$schema": "/r/schemas/item/rev/" + sch.ID, "title": "zq a"}))
	if e := must(ad.RotateEpoch(ctx, "e", idxPriv.PublicKey())); e != 2 {
		t.Fatalf("rotated to %d", e)
	}
	must(ad.CreateDocSealed(ctx, "e", "b", map[string]any{"$schema": "/r/schemas/item/rev/" + sch.ID, "title": "zq b"}))
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"e"}, []string{"read"}, map[string]any{"enc": idxJWK})),
		client.WithKeyringSenders(adminPriv.PublicKey()))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"e"}, untyped: true, now: s.Now}, func(o *indexOpts) { o.Recipient = idxPriv })
	x.caughtUp("e")
	f := x.fetch("/e?q=zq", "")
	if got := p37Kids(t, f.body); fmt.Sprint(got) != "map[a:e#1 b:e#2]" {
		t.Fatalf("kids %v", got)
	}
	for _, h := range decodeJSON(t, f.body)["hits"].([]any) {
		h := h.(map[string]any)
		name := h["resource"].(string)
		keyOf := func(kid string) []byte { return must(ad.Key(ctx, kid)) }
		if _, err := derived.OpenItem(h["sealed"].(string), derived.ItemKey(keyOf, "e", name), derived.View{NS: "e", Target: f.path}, "e", name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// pageSchemaWith is a schema whose properties are props and related, an
// array of references (x-ref) for /_refs.
func pageSchemaWith(props map[string]any) map[string]any {
	p := map[string]any{"$schema": map[string]any{"type": "string"}, "$nonce": map[string]any{"type": "string"},
		"related": map[string]any{"type": "array", "items": map[string]any{"type": "string", "x-ref": map[string]any{}}}}
	for k, v := range props {
		p[k] = v
	}
	return map[string]any{"$schema": d2020, "type": "object", "properties": p}
}
