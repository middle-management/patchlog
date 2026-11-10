package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/ids"
)

// V75-03 (v0.75): filtered namespace reads at the origin (§B.11.9): the
// redirects of partial readers, the /ns/{ns}/g/{gs} routes, filtered
// /heads, ranges, long-poll and events, /branches, the gestures listing,
// and ?prefix= on /heads for every reader (§7.4).

// v75s is a server with authentication on and §B.11.3's catalog setup, as
// the core's v75World: cat-season trusts matches, whose key catalog-01 has
// requireAt cat-season and a scope rule testing /resource by type, so its
// grants read matches only in part. k is a * key in both.
type v75s struct {
	*tenv
	ck    *edge.Cookies
	k     keyPair
	cat   keyPair
	admin string
}

type v75sOpts struct {
	env     []envOpt
	matches func(doc map[string]any)
}

func newV75s(t *testing.T, o v75sOpts) *v75s {
	t.Helper()
	ck := edge.NewCookies("", nil)
	var priv ed25519.PrivateKey
	fast := func(o *core.Options) {
		if o.Maximums == (core.Limits{}) {
			o.Maximums = core.DefaultLimits()
		}
		o.Maximums.ExchangeRate = core.Rate{Rate: 1e9, Burst: 1e9}
	}
	e := newEnvWith(t, []Option{WithEdgeGrants(ck)}, append([]envOpt{withAuth(&priv), fast}, o.env...)...)
	e.opPriv = priv
	w := &v75s{tenv: e, ck: ck, k: newKey("k"), cat: newKey("catalog-01")}
	cat := map[string]any{"read": "grant", "keys": []any{w.k.entry("*")}, "catalog": map[string]any{"trust": []any{"matches"}}}
	w.mkNS("cat-season", cat)
	matches := map[string]any{"read": "grant", "keys": []any{w.k.entry("*"), map[string]any{"kid": "catalog-01", "alg": "ed25519", "pub": w.cat.pub,
		"can": []any{"read"}, "requireAt": "cat-season", "maxTtl": "PT15M",
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}}},
		"roles":    map[string]any{"reader": map[string]any{"can": []any{"read"}}},
		"catalogs": map[string]any{"cat-season": map[string]any{"place": []any{}}}}
	if o.matches != nil {
		o.matches(matches)
	}
	w.mkNS("matches", matches)
	w.admin = e.grant(w.k, "user:root", []string{"cat-season", "matches", "matches-r7"},
		[]string{"read", "create", "append", "delete", "restore", "purge", "purge-ns", "config", "branch"})
	return w
}

func v75sParents(names ...string) []any {
	out := []any{}
	for _, n := range names {
		out = append(out, map[string]any{"href": "/r/cat-season/" + n})
	}
	return out
}

// seed writes root, whose $access gives editors and li reader, season
// under it, embargo for chiefs alone, and the placements of placed under
// season and hidden under embargo; and every name of docs in matches.
func (w *v75s) seed(placed, hidden, docs []string) {
	w.t.Helper()
	w.put("cat-season", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:editors": []any{"reader"}, "user:li": []any{"reader"}}})
	w.put("cat-season", "season", map[string]any{"parents": v75sParents("root")})
	w.put("cat-season", "embargo", map[string]any{"parents": v75sParents("root"), "$access": map[string]any{"inherit": false, "group:chiefs": []any{"reader"}}})
	for _, n := range placed {
		w.put("cat-season", "matches."+n, map[string]any{"parents": v75sParents("season")})
	}
	for _, n := range hidden {
		w.put("cat-season", "matches."+n, map[string]any{"parents": v75sParents("embargo")})
	}
	for _, n := range docs {
		w.put("matches", n, map[string]any{"title": n})
	}
}

// put creates or replaces ns/name with doc, as admin.
func (w *v75s) put(ns, name string, doc map[string]any, hdr ...map[string]string) string {
	w.t.Helper()
	q := req{method: "PATCH", path: "/r/" + ns + "/" + name, bearer: w.admin}
	if len(hdr) > 0 {
		q.hdr = hdr[0]
	}
	if r := w.get("/r/"+ns+"/"+name, w.admin); r.Code == 302 {
		q.ifMatch, q.body = etagOf(r), []any{map[string]any{"op": "replace", "path": "", "value": doc}}
	} else {
		q.ifNoneMatch, q.body = "*", addRoot(doc)
	}
	r := w.do(q)
	expect(w.t, r, 201)
	return etagOf(r)
}

// li is a partial reader of matches: catalog-01's grant for user:li, in
// editors and interns, with the reader role.
func (w *v75s) li(extra ...map[string]any) string {
	return w.catGrant("user:li", []any{"editors", "interns"}, extra...)
}

// bo is a partial reader in chiefs alone, who sees what embargo holds.
func (w *v75s) bo() string { return w.catGrant("user:bo", []any{"chiefs"}) }

func (w *v75s) catGrant(sub string, groups []any, extra ...map[string]any) string {
	w.t.Helper()
	x := map[string]any{"groups": groups, "roles": []any{"reader"}, "at": map[string]any{"ns": "cat-season", "id": w.nsHead("cat-season", w.admin)},
		"exp": w.clock.Now().Add(10 * time.Minute).Format(time.RFC3339)}
	for _, m := range extra {
		for k, v := range m {
			x[k] = v
		}
	}
	return w.grant(w.cat, sub, []string{"matches"}, []string{"read"}, x)
}

// filtered follows a partial reader's redirect from /rev/{head}/heads
// and returns the gs and at it names.
func (w *v75s) filtered(bearer string) (gs, at string) {
	w.t.Helper()
	r := w.get("/ns/matches/rev/"+w.nsHead("matches", w.admin)+"/heads", bearer)
	expect(w.t, r, 302)
	loc := r.H.Get("Location")
	parts := strings.Split(strings.SplitN(loc, "?", 2)[0], "/")
	if len(parts) != 8 || parts[3] != "g" || parts[5] != "at" || parts[7] != "heads" {
		w.t.Fatalf("Location %q", loc)
	}
	return parts[4], parts[6]
}

// cookie exchanges bearer for its /ns/matches/g/{gs} cookie.
func (w *v75s) cookie(bearer string) (*http.Cookie, string) {
	w.t.Helper()
	r := w.do(req{method: "POST", path: "/edge-grants", bearer: bearer})
	expect(w.t, r, 200)
	for p, c := range edgeCookies(w.t, r) {
		if strings.HasPrefix(p, "/ns/matches/g/") {
			return c, strings.TrimPrefix(p, "/ns/matches/g/")
		}
	}
	w.t.Fatalf("no g cookie: %v", r.H.Values("Set-Cookie"))
	return nil, ""
}

func expectPrivateNoStore(t *testing.T, r *resp) {
	t.Helper()
	if r.H.Get("Cache-Control") != "private, no-store" || r.H.Get("CDN-Cache-Control") != "no-store" || r.H.Get("Surrogate-Control") != "no-store" {
		t.Fatalf("cache headers %v", r.H)
	}
}

func headNames(t *testing.T, r *resp) []string {
	t.Helper()
	out := []string{}
	for _, x := range r.Obj()["heads"].([]any) {
		out = append(out, x.(map[string]any)["resource"].(string))
	}
	return out
}

// §7.4, §12.4: ?prefix= on /heads, for every reader: only names starting
// with it, next absent on the last page, read-through names of a branch
// included; one that isn't a resource name is 400, before authorisation.
func TestV075HeadsPrefix(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withLogPageSize(1))
	e.mkNS("n", map[string]any{})
	for _, n := range []string{"a1", "a2", "b1"} {
		e.create("n", n, map[string]any{"n": n})
	}
	head := e.nsHead("n")
	page := func(ns, id, q string) *resp {
		e.t.Helper()
		return e.get("/ns/" + ns + "/rev/" + id + "/heads?" + q)
	}
	r := page("n", head, "prefix=a")
	expect(t, r, 200)
	if got := headNames(t, r); !reflect.DeepEqual(got, []string{"a1"}) || r.Str("next") != "a1" {
		t.Fatalf("page 1 %s", r.Body)
	}
	r = page("n", head, "prefix=a&after=a1")
	if got := headNames(t, r); !reflect.DeepEqual(got, []string{"a2"}) || r.Obj()["next"] != nil {
		t.Fatalf("page 2 %s", r.Body)
	}
	// An after below the prefix starts at it; one above its range is an
	// empty page.
	if r = page("n", head, "prefix=b&after=a"); !reflect.DeepEqual(headNames(t, r), []string{"b1"}) || r.Obj()["next"] != nil {
		t.Fatalf("after below %s", r.Body)
	}
	if r = page("n", head, "prefix=a&after=b"); len(headNames(t, r)) != 0 || r.Obj()["next"] != nil {
		t.Fatalf("after above %s", r.Body)
	}
	for _, bad := range []string{"prefix=.x", "prefix=", "prefix=A", "prefix=a&prefix=b"} {
		expectCode(t, page("n", head, bad), 400, "bad_input")
	}
	// Request shape: before the namespace is looked up.
	expectCode(t, page("nope", head, "prefix=.x"), 400, "bad_input")

	// A branch's read-through names honour it, with its own.
	expect(t, e.do(req{method: "POST", path: "/ns/n/branches", ifNoneMatch: "*", author: "admin",
		body: map[string]any{"name": "n-b", "at": head, "patches": []any{}}}), 201)
	e.create("n-b", "a3", map[string]any{"n": "a3"})
	e.create("n-b", "c1", map[string]any{"n": "c1"})
	bh := e.nsHead("n-b")
	var got []string
	for after := ""; ; {
		r := page("n-b", bh, "prefix=a&after="+after)
		expect(t, r, 200)
		got = append(got, headNames(t, r)...)
		if after = r.Str("next"); after == "" {
			break
		}
	}
	if !reflect.DeepEqual(got, []string{"a1", "a2", "a3"}) {
		t.Fatalf("branch with prefix: %v", got)
	}
}

// §B.11.9 URLs, Answers (scenario 59): a partial reader's request at an
// unfiltered URL is 302 to its filtered form, ranges at the current at,
// private, no-store, by the grant in Authorization; GET /ns/{ns} is the
// head pointer, and /rev/{ns_id} stays 403. Uncovered, as before v0.75.
func TestV075PartialRedirects(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	li := w.li()
	head := w.nsHead("matches", w.admin)
	gs, at := w.filtered(li)
	base := "/ns/matches/g/" + gs
	cases := []struct{ path, loc string }{
		{"/ns/matches/rev/" + head + "/heads?after=a&prefix=d", base + "/at/" + at + "/heads?after=a&prefix=d"},
		{"/ns/matches/rev/" + head + "/heads", base + "/at/" + at + "/heads"},
		{"/ns/matches/rev/" + head + "/log?since=" + head, base + "/at/" + at + "/log?since=" + head},
		{"/ns/matches/log?since=" + head, base + "/at/" + at + "/log?since=" + head},
		{"/ns/matches/log?live=long-poll&since=" + head, base + "/log?live=long-poll&since=" + head},
		{"/ns/matches/events?since=" + head, base + "/events?since=" + head},
	}
	for _, c := range cases {
		r := w.get(c.path, li)
		expect(t, r, 302)
		expectPrivateNoStore(t, r)
		if r.H.Get("Location") != c.loc || !strings.Contains(r.H.Get("Vary"), "Authorization") {
			t.Fatalf("%s: Location %q, Vary %q, want %q", c.path, r.H.Get("Location"), r.H.Get("Vary"), c.loc)
		}
	}
	// The redirect followed with the grant reads.
	r := w.get(base+"/at/"+at+"/heads", li)
	expect(t, r, 200)
	if !reflect.DeepEqual(headNames(t, r), []string{"derby"}) {
		t.Fatalf("filtered heads %s", r.Body)
	}
	// GET /ns/{ns}: the head pointer.
	r = w.get("/ns/matches", li)
	expect(t, r, 302)
	if r.H.Get("Location") != "/ns/matches/rev/"+head || etagOf(r) != head || r.H.Get("X-Config-Revision") == "" {
		t.Fatalf("head pointer %v", r.H)
	}
	expect(t, w.get("/ns/matches/rev/"+head, li), 403)
	expect(t, w.get("/ns/matches/rev/"+head, w.admin), 200)
	// Unrestricted readers keep the unfiltered answers.
	expect(t, w.get("/ns/matches/rev/"+head+"/heads", w.admin), 200)

	// Uncovered: NoFilteredReads, or a namespace trusting no catalog.
	for _, o := range []v75sOpts{
		{env: []envOpt{func(o *core.Options) { o.NoFilteredReads = true }}},
		{matches: func(doc map[string]any) { delete(doc, "catalogs") }},
	} {
		w2 := newV75s(t, o)
		w2.seed([]string{"derby"}, nil, []string{"derby"})
		h2 := w2.nsHead("matches", w2.admin)
		expect(t, w2.get("/ns/matches/rev/"+h2+"/heads", w2.li()), 403)
		expect(t, w2.get("/ns/matches/rev/"+h2+"/log", w2.li()), 403)
		expect(t, w2.get("/ns/matches/events", w2.li()), 403)
		expect(t, w2.get("/ns/matches", w2.li()), 403)
		expect(t, w2.get("/ns/matches/g/"+ids.Of([]byte("x")).String()+"/heads", w2.li()), 403)
	}
}

// §B.11.9 URLs (scenario 89): a URL under /ns/{ns}/g/{gs} without at is
// 302 to its form at the current at, private, no-store, under the cookie;
// an at the origin can't answer is too; gs and at are ids (400).
func TestV075FilteredRoutes(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	c, gs := w.cookie(w.li())
	gsBearer, at := w.filtered(w.li())
	if gs != gsBearer {
		t.Fatalf("cookie gs %s, grant gs %s", gs, gsBearer)
	}
	ck := cookieHdr(c)
	base := "/ns/matches/g/" + gs
	head := w.nsHead("matches", w.admin)
	for path, loc := range map[string]string{
		base + "/heads?prefix=d":                    base + "/at/" + at + "/heads?prefix=d",
		base + "/log?since=" + head:                 base + "/at/" + at + "/log?since=" + head,
		base + "/at/" + head + "/heads":             base + "/at/" + at + "/heads",
		base + "/at/" + head + "/log?since=" + head: base + "/at/" + at + "/log?since=" + head,
	} {
		r := w.do(req{method: "GET", path: path, hdr: ck})
		expect(t, r, 302)
		expectPrivateNoStore(t, r)
		if r.H.Get("Location") != loc {
			t.Fatalf("%s: Location %q, want %q", path, r.H.Get("Location"), loc)
		}
	}
	r := w.do(req{method: "GET", path: base + "/at/" + at + "/heads", hdr: ck})
	expect(t, r, 200)
	if !reflect.DeepEqual(headNames(t, r), []string{"derby"}) {
		t.Fatalf("under the cookie %s", r.Body)
	}
	// Malformed ids, and "all", are request-shape 400s.
	for _, p := range []string{"/ns/matches/g/all/heads", "/ns/matches/g/xyz/at/" + at + "/heads", base + "/at/all/log", base + "/at/zz/heads",
		base + "/heads?prefix=.x", base + "/log?live=x", base + "/events?since=bad", base + "/heads?since=" + head} {
		expectCode(t, w.do(req{method: "GET", path: p, hdr: ck}), 400, "bad_input")
	}
	// The cookie covers its own gs alone; no credentials are 401.
	other := "/ns/matches/g/" + ids.Of([]byte("other")).String()
	expect(t, w.do(req{method: "GET", path: other + "/heads", hdr: ck}), 401)
	expect(t, w.get(base+"/at/"+at+"/heads"), 401)
	// A grant reads at its own gs alone.
	expect(t, w.get(other+"/heads", w.li()), 403)
	// An unrestricted reader's grant is 403 there.
	expect(t, w.get(base+"/at/"+at+"/heads", w.admin), 403)
}

// §B.11.9 /heads, URLs (scenarios 66, 82): only visible rows, pages filled
// to logPageSize, next on every full page and no other; tagged as the
// unfiltered /heads plus ns:{x} for the rest of at, with
// X-Namespace-Revision.
func TestV075FilteredHeads(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{env: []envOpt{withLogPageSize(1)}})
	w.seed([]string{"a", "c"}, []string{"b"}, []string{"a", "b", "c", "d"})
	li := w.li()
	gs, at := w.filtered(li)
	head := w.nsHead("matches", w.admin)
	base := "/ns/matches/g/" + gs + "/at/" + at + "/heads"
	var pages [][]string
	var nexts []string
	for after := ""; ; {
		r := w.get(base+"?after="+after, li)
		expect(t, r, 200)
		pages, nexts = append(pages, headNames(t, r)), append(nexts, r.Str("next"))
		if r.H.Get("X-Namespace-Revision") != head {
			t.Fatalf("X-Namespace-Revision %q, want %q", r.H.Get("X-Namespace-Revision"), head)
		}
		tags := strings.Split(r.H.Get("Cache-Tag"), ",")
		for _, want := range []string{"ns:matches", "heads:matches", "ns:cat-season", "heads:cat-season"} {
			if !strings.Contains(","+r.H.Get("Cache-Tag")+",", ","+want+",") {
				t.Fatalf("Cache-Tag %v lacks %s", tags, want)
			}
		}
		if r.H.Get("Cache-Control") != "private, max-age=300" {
			t.Fatalf("Cache-Control %q", r.H.Get("Cache-Control"))
		}
		if after = r.Str("next"); after == "" {
			break
		}
	}
	if !reflect.DeepEqual(pages, [][]string{{"a"}, {"c"}, {}}) || !reflect.DeepEqual(nexts, []string{"a", "c", ""}) {
		t.Fatalf("pages %v, nexts %v", pages, nexts)
	}
	// prefix bounds the visible rows.
	r := w.get(base+"?prefix=c", li)
	if !reflect.DeepEqual(headNames(t, r), []string{"c"}) || r.Str("next") != "c" {
		t.Fatalf("prefix %s", r.Body)
	}
	if r = w.get(base+"?prefix=b", li); len(headNames(t, r)) != 0 || r.Obj()["next"] != nil {
		t.Fatalf("hidden prefix %s", r.Body)
	}
	// bo, in chiefs, sees b alone.
	bo := w.bo()
	bgs, bat := w.filtered(bo)
	if bgs == gs {
		t.Fatal("bo shares li's gs")
	}
	r = w.get("/ns/matches/g/"+bgs+"/at/"+bat+"/heads", bo)
	if !reflect.DeepEqual(headNames(t, r), []string{"b"}) {
		t.Fatalf("bo %s", r.Body)
	}
}

// v75Batch writes a batch to matches as admin.
func (w *v75s) batch(body map[string]any) *resp {
	w.t.Helper()
	r := w.do(req{method: "POST", path: "/ns/matches/batch", body: body, bearer: w.admin})
	expect(w.t, r, 201)
	return r
}

func v75Item(name string, doc map[string]any) map[string]any {
	return map[string]any{"resource": name, "ifNoneMatch": "*", "steps": []any{addRoot(doc)}}
}

// readRange reads a filtered range page by page from since, returning the
// entries and checking X-Log-Next and X-Namespace-Revision.
func (w *v75s) readRange(gs, at, since, bearer string) (entries []map[string]any, pages int) {
	w.t.Helper()
	end := ""
	for {
		r := w.get("/ns/matches/g/"+gs+"/at/"+at+"/log?since="+since, bearer)
		expect(w.t, r, 200)
		pages++
		if end == "" {
			end = r.H.Get("X-Namespace-Revision")
		} else if r.H.Get("X-Namespace-Revision") != end {
			w.t.Fatalf("X-Namespace-Revision moved: %q, %q", end, r.H.Get("X-Namespace-Revision"))
		}
		for _, x := range r.Arr() {
			entries = append(entries, x.(map[string]any))
		}
		next := r.H.Get("X-Log-Next")
		if next == "" {
			return entries, pages
		}
		since = next
	}
}

// §B.11.9 Log entries, Log ranges (scenarios 67, 73, 83): a batch shows its
// visible entries, gestures and source.ids only; config-only where it
// changed the document; dropped otherwise; a batch counts as its visible
// items; branch entries never; the last page lacks X-Log-Next.
func TestV075FilteredLog(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{env: []envOpt{withLogPageSize(2)}})
	w.seed([]string{"derby", "shared"}, []string{"secret"}, nil)
	li := w.li()
	from := w.nsHead("matches", w.admin)
	src := w.put("matches", "src", map[string]any{"n": 1}) // hidden: unplaced
	srcNS := w.nsHead("matches", w.admin)
	// 1: derby and secret, with gestures and source.ids.
	w.batch(map[string]any{"gesture": gA, "items": []any{v75Item("derby", map[string]any{"t": "d"}), v75Item("secret", map[string]any{"t": "s"})},
		"source": map[string]any{"ns": "matches", "at": from, "ids": map[string]any{"derby": src, "secret": src}}})
	// 2: a config change and secret2: config-only.
	cfg := w.get("/ns/matches", w.admin).H.Get("X-Config-Revision")
	w.batch(map[string]any{"config": map[string]any{"ifMatch": cfg, "patches": []any{op("add", "/x-note", "n")}},
		"items": []any{v75Item("secret2", map[string]any{})}})
	// 3: hidden alone: dropped.
	w.batch(map[string]any{"items": []any{v75Item("secret3", map[string]any{})}})
	// 4: one visible and twenty hidden items: one unit, so 5 shares its page.
	items := []any{v75Item("shared", map[string]any{})}
	for i := range 20 {
		items = append(items, v75Item("h"+strconv.Itoa(i), map[string]any{}))
	}
	w.batch(map[string]any{"items": items})
	// 5: a branch entry, never shown.
	expect(t, w.do(req{method: "POST", path: "/ns/matches/branches", ifNoneMatch: "*", bearer: w.admin,
		body: map[string]any{"name": "matches-r7", "at": w.nsHead("matches", w.admin), "patches": []any{}}}), 201)

	gs, at := w.filtered(li)
	entries, pages := w.readRange(gs, at, from, li)
	var kinds []string
	for _, e := range entries {
		kinds = append(kinds, e["kind"].(string))
	}
	if !reflect.DeepEqual(kinds, []string{"batch", "batch", "batch"}) {
		t.Fatalf("kinds %v: %v", kinds, entries)
	}
	b1, b2, b4 := entries[0], entries[1], entries[2]
	if es := b1["entries"].([]any); len(es) != 1 || es[0].(map[string]any)["resource"] != "derby" {
		t.Fatalf("batch 1 entries %v", b1)
	}
	if g := b1["gestures"].(map[string]any); len(g) != 1 || g["derby"] == nil {
		t.Fatalf("batch 1 gestures %v", b1["gestures"])
	}
	if ids := b1["source"].(map[string]any)["ids"].(map[string]any); len(ids) != 1 || ids["derby"] != src {
		t.Fatalf("batch 1 source %v", b1["source"])
	}
	if es := b2["entries"].([]any); len(es) != 1 || es[0].(map[string]any)["kind"] != "config" {
		t.Fatalf("batch 2 %v", b2)
	}
	if es := b4["entries"].([]any); len(es) != 1 || es[0].(map[string]any)["resource"] != "shared" {
		t.Fatalf("batch 4 %v", b4)
	}
	// src, 1, 2, 3, 4+5: hidden entries and the dropped batch count one
	// each, batch 4 as its one visible item.
	if pages != 3 {
		t.Fatalf("%d pages", pages)
	}
	// Entries are the unrestricted range's, ids and prev included: prev
	// names the entry before, hidden or not (§B.11.9 Log entries).
	full := map[string]map[string]any{}
	for since := from; since != ""; {
		r := w.get("/ns/matches/rev/"+w.nsHead("matches", w.admin)+"/log?since="+since, w.admin)
		expect(t, r, 200)
		for _, x := range r.Arr() {
			full[x.(map[string]any)["id"].(string)] = x.(map[string]any)
		}
		since = r.H.Get("X-Log-Next")
	}
	for _, e := range entries {
		u := full[e["id"].(string)]
		if u == nil || e["prev"] != u["prev"] || e["author"] != u["author"] || e["created"] != u["created"] {
			t.Fatalf("entry %v, unfiltered %v", e, u)
		}
	}
	if b1["prev"] != srcNS {
		t.Fatalf("batch 1's prev %v, want the hidden %s", b1["prev"], srcNS)
	}
	// A since not in the chain is 404, short, tagged.
	r := w.get("/ns/matches/g/"+gs+"/at/"+at+"/log?since="+ids.Of([]byte("nope")).String(), li)
	expect(t, r, 404)
	if !strings.Contains(r.H.Get("Cache-Tag"), "ns:cat-season") || r.H.Get("X-Namespace-Revision") == "" {
		t.Fatalf("404 headers %v", r.H)
	}
}

// longPollRes is a long-poll's answer.
type longPollRes struct {
	code int
	rev  string
	body []byte
	took time.Duration
}

func (w *v75s) longPoll(path, bearer string) longPollRes {
	w.t.Helper()
	start := time.Now()
	r := w.get(path, bearer)
	return longPollRes{r.Code, r.H.Get("X-Namespace-Revision"), r.Body, time.Since(start)}
}

// waitCursor is the cursor of the current long-poll interval, after
// waiting out one that ends within margin, so a poll with it waits.
func waitCursor(interval, margin time.Duration) int64 {
	now := time.Now()
	cur := now.UnixNano() / int64(interval)
	if end := time.Unix(0, (cur+1)*int64(interval)); time.Until(end) < margin {
		time.Sleep(time.Until(end) + 10*time.Millisecond)
		cur++
	}
	return cur
}

// §B.11.9 Long-poll (scenario 72): only visible entries answer 200 or end
// a wait; an interval with none ends 204, its X-Namespace-Revision the
// newest entry scanned, which the next poll is accepted with.
func TestV075FilteredLongPoll(t *testing.T) {
	t.Parallel()
	interval := 2 * time.Second
	w := newV75s(t, v75sOpts{env: []envOpt{withLongPoll(interval), withLogPageSize(5)}})
	w.seed([]string{"derby"}, nil, nil)
	li := w.li()
	gs, _ := w.filtered(li)
	lp := "/ns/matches/g/" + gs + "/log?live=long-poll&since="
	since := w.nsHead("matches", w.admin)
	// Answered at once: twenty hidden entries are scanned past, page by
	// page, to 204 with the newest.
	for i := range 20 {
		w.put("matches", "h"+strconv.Itoa(i), map[string]any{})
	}
	res := w.longPoll(lp+since, li)
	if newest := w.nsHead("matches", w.admin); res.code != 204 || res.rev != newest {
		t.Fatalf("at once: %d %q, want 204 %q", res.code, res.rev, newest)
	}
	// Waiting: hidden writes during the interval don't end it.
	since = res.rev
	cur := waitCursor(interval, 1500*time.Millisecond)
	done := make(chan longPollRes, 1)
	go func() { done <- w.longPoll(lp+since+"&cursor="+strconv.FormatInt(cur, 10), li) }()
	time.Sleep(200 * time.Millisecond)
	for i := range 3 {
		w.put("matches", "w"+strconv.Itoa(i), map[string]any{})
	}
	newest := w.nsHead("matches", w.admin)
	res = <-done
	if res.code != 204 || res.rev != newest {
		t.Fatalf("waiting: %d %q %s, want 204 %q", res.code, res.rev, res.body, newest)
	}
	// The next poll from it is accepted, and a visible write answers it.
	since = res.rev
	cur = waitCursor(interval, 1500*time.Millisecond)
	go func() { done <- w.longPoll(lp+since+"&cursor="+strconv.FormatInt(cur, 10), li) }()
	time.Sleep(200 * time.Millisecond)
	w.put("matches", "w9", map[string]any{})
	w.put("matches", "derby", map[string]any{"v": 2})
	res = <-done
	if res.code != 200 || !strings.Contains(string(res.body), `"derby"`) || strings.Contains(string(res.body), "w9") ||
		res.rev != w.nsHead("matches", w.admin) {
		t.Fatalf("visible: %d %q %s", res.code, res.rev, res.body)
	}
}

// §B.11.9 Cost: waiters of two subject sets on one since are answered
// apart: a write visible to one gs alone answers it 200 and the other 204.
func TestV075FilteredLongPollPerGS(t *testing.T) {
	t.Parallel()
	interval := 2 * time.Second
	w := newV75s(t, v75sOpts{env: []envOpt{withLongPoll(interval)}})
	w.seed([]string{"derby"}, []string{"secret"}, []string{"secret"})
	li, bo := w.li(), w.bo()
	lgs, _ := w.filtered(li)
	bgs, _ := w.filtered(bo)
	since := w.nsHead("matches", w.admin)
	cur := strconv.FormatInt(waitCursor(interval, 1500*time.Millisecond), 10)
	lc, bc := make(chan longPollRes, 1), make(chan longPollRes, 1)
	go func() { lc <- w.longPoll("/ns/matches/g/"+lgs+"/log?live=long-poll&cursor="+cur+"&since="+since, li) }()
	go func() { bc <- w.longPoll("/ns/matches/g/"+bgs+"/log?live=long-poll&cursor="+cur+"&since="+since, bo) }()
	time.Sleep(200 * time.Millisecond)
	w.put("matches", "derby", map[string]any{})
	l, b := <-lc, <-bc
	if l.code != 200 || !strings.Contains(string(l.body), "derby") {
		t.Fatalf("li: %d %s", l.code, l.body)
	}
	if b.code != 204 || b.rev != w.nsHead("matches", w.admin) {
		t.Fatalf("bo: %d %q", b.code, b.rev)
	}
}

// v75Event is one server-sent event.
type v75Event struct{ event, id, data string }

// events opens an event stream and sends its events on the channel, which
// is closed when the stream ends.
func (w *v75s) events(ctx context.Context, path, bearer string) (*http.Response, <-chan v75Event) {
	w.t.Helper()
	hr, _ := http.NewRequestWithContext(ctx, "GET", w.srv.URL+path, nil)
	hr.Header.Set("Authorization", "Bearer "+bearer)
	r, err := client.Do(hr)
	if err != nil {
		w.t.Fatal(err)
	}
	ch := make(chan v75Event, 64)
	go func() {
		defer close(ch)
		defer r.Body.Close()
		sc := bufio.NewScanner(r.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		var ev v75Event
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.event != "" {
					ch <- ev
				}
				ev = v75Event{}
			case strings.HasPrefix(line, "event: "):
				ev.event = line[7:]
			case strings.HasPrefix(line, "id: "):
				ev.id = line[4:]
			case strings.HasPrefix(line, "data: "):
				ev.data = line[6:]
			}
		}
	}()
	return r, ch
}

// next is the stream's next event, or false after d.
func nextEvent(ch <-chan v75Event, d time.Duration) (v75Event, bool) {
	select {
	case ev, ok := <-ch:
		return ev, ok
	case <-time.After(d):
		return v75Event{}, false
	}
}

// §B.11.9 Events (scenario 81): only visible entries, judged again at the
// current checkpoint with each read check: thirty hidden entries and one
// visible yield one event; once derby's placement leaves li's view, its
// later entries aren't sent.
func TestV075FilteredEvents(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{env: []envOpt{withLogPageSize(4)}})
	w.seed([]string{"derby", "shared"}, nil, []string{"derby", "shared"})
	li := w.li()
	gs, _ := w.filtered(li)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, ch := w.events(ctx, "/ns/matches/g/"+gs+"/events?since="+w.nsHead("matches", w.admin), li)
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("stream %d %v", r.StatusCode, r.Header)
	}
	for i := range 30 {
		w.put("matches", "h"+strconv.Itoa(i), map[string]any{})
	}
	w.put("matches", "derby", map[string]any{"v": 1})
	ev, ok := nextEvent(ch, 5*time.Second)
	if !ok || ev.event != "head" || !strings.Contains(ev.data, `"resource":"derby"`) {
		t.Fatalf("first event %+v %v", ev, ok)
	}
	if ev, ok := nextEvent(ch, 300*time.Millisecond); ok {
		t.Fatalf("a second event %+v", ev)
	}
	// derby's placement moves under embargo, out of li's view.
	w.put("cat-season", "embargo", map[string]any{"parents": v75sParents("root"), "$access": map[string]any{"inherit": false, "group:chiefs": []any{"reader"}}})
	w.put("cat-season", "matches.derby", map[string]any{"parents": v75sParents("embargo")})
	w.put("matches", "derby", map[string]any{"v": 2})
	w.put("matches", "shared", map[string]any{"v": 2})
	ev, ok = nextEvent(ch, 5*time.Second)
	if !ok || !strings.Contains(ev.data, `"resource":"shared"`) {
		t.Fatalf("after the move %+v %v", ev, ok)
	}
	// Once the rules its gs digests change, the next read check fails
	// and the stream ends, sending nothing more.
	expect(t, w.patchNS("matches", ops(op("add", "/roles/reader/rules", []any{map[string]any{"op": "test", "path": "/action", "value": "read"}})), w.admin), 201)
	w.put("matches", "shared", map[string]any{"v": 3})
	select {
	case ev, ok := <-ch:
		if ok {
			t.Fatalf("after the rules changed %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stream outlived its read check")
	}
	li = w.li()
	gs, _ = w.filtered(li)
	// Last-Event-ID may name a hidden entry.
	w.put("matches", "h99", map[string]any{})
	hid := w.nsHead("matches", w.admin)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	hr, _ := http.NewRequestWithContext(ctx2, "GET", w.srv.URL+"/ns/matches/g/"+gs+"/events", nil)
	hr.Header.Set("Authorization", "Bearer "+li)
	hr.Header.Set("Last-Event-ID", hid)
	r2, err := client.Do(hr)
	if err != nil || r2.StatusCode != 200 {
		t.Fatalf("Last-Event-ID naming a hidden entry: %v %v", r2, err)
	}
	r2.Body.Close()
}

// §B.11.9 Answers (TDA 68; v0.78: "a partial reader's /branches is 403"):
// /branches to a partial reader is 403, a grant also naming the branch
// included. Before v0.78 it listed, private, no-store, the local branches
// its grant verified in. It passes once ACCESS-9's reads.go change is in
// (V81-01).
func TestV075BranchesPartial(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	expect(t, w.do(req{method: "POST", path: "/ns/matches/branches", ifNoneMatch: "*", bearer: w.admin,
		body: map[string]any{"name": "matches-r7", "at": w.nsHead("matches", w.admin), "patches": []any{}}}), 201)
	expect(t, w.get("/ns/matches/branches", w.li()), 403)
	both := w.grant(w.cat, "user:li", []string{"matches", "matches-r7"}, []string{"read"}, map[string]any{"groups": []any{"editors"},
		"roles": []any{"reader"}, "at": map[string]any{"ns": "cat-season", "id": w.nsHead("cat-season", w.admin)},
		"exp": w.clock.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	expect(t, w.get("/ns/matches/branches", both), 403)
	// Unrestricted: the head pointer class, as before.
	r := w.get("/ns/matches/branches", w.admin)
	expect(t, r, 200)
	if r.H.Get("Cache-Control") != "private, max-age=0" || len(r.Arr()) != 1 {
		t.Fatalf("admin %v %s", r.H, r.Body)
	}
}

// §B.11.9 Purged namespaces, §8.5: filtered /heads are 410 after
// admission; the range stays readable and ends with purge-ns; events and
// long-poll from purge-ns are 410.
func TestV075FilteredPurged(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	li := w.li()
	from := w.nsHead("matches", w.admin)
	opg := mint(t, w.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"matches"}, "can": []any{"purge-ns"},
		"exp": w.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	expect(t, w.patchNS("matches", ops(op("add", "/frozen", true)), w.admin), 201)
	expect(t, w.do(req{method: "POST", path: "/ns/matches/purge?force=1", ifMatch: w.nsHead("matches", w.admin), bearer: opg}), 204)
	purgeNS := w.nsHead("matches", w.admin)
	gs, at := w.filtered(li)
	r := w.get("/ns/matches/g/"+gs+"/at/"+at+"/heads", li)
	expectCode(t, r, 410, "purged")
	// As the unfiltered /heads' 410, tagged as filtered answers are.
	u := w.get("/ns/matches/rev/"+purgeNS+"/heads", w.admin)
	expectCode(t, u, 410, "purged")
	if r.H.Get("Cache-Control") != u.H.Get("Cache-Control") || !strings.Contains(r.H.Get("Cache-Tag"), "ns:cat-season") {
		t.Fatalf("410 headers %v, unfiltered %v", r.H, u.H)
	}
	entries, _ := w.readRange(gs, at, from, li)
	if len(entries) == 0 || entries[len(entries)-1]["kind"] != "purge-ns" || entries[len(entries)-1]["id"] != purgeNS {
		t.Fatalf("range %v", entries)
	}
	expectCode(t, w.get("/ns/matches/g/"+gs+"/events?since="+purgeNS, li), 410, "purged")
	expectCode(t, w.get("/ns/matches/g/"+gs+"/log?live=long-poll&since="+purgeNS, li), 410, "purged")
}

// §B.11.9 with the client of V75-02: a partial reader's FilteredHeads,
// FilteredLog and FilteredLongPoll follow this server's redirects and read
// what is visible; LongPoll names the filtered form without following it.
func TestV075ClientFiltered(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{env: []envOpt{withLogPageSize(2)}})
	w.seed([]string{"derby", "shared"}, []string{"secret"}, []string{"derby", "secret", "shared", "opener"})
	ctx := context.Background()
	c, err := plclient.New(w.srv.URL, plclient.WithHTTPClient(&http.Client{Transport: transport}), plclient.WithBearer(w.li()))
	if err != nil {
		t.Fatal(err)
	}
	head := w.nsHead("matches", w.admin)
	items, fa, err := c.FilteredHeads(ctx, "matches", head, "")
	if err != nil || !fa.Filtered() || fa.End != head {
		t.Fatalf("FilteredHeads: %v %+v", err, fa)
	}
	var names []string
	for _, it := range items {
		names = append(names, it.Resource)
	}
	if !reflect.DeepEqual(names, []string{"derby", "shared"}) {
		t.Fatalf("heads %v", names)
	}
	if items, _, err = c.FilteredHeads(ctx, "matches", head, "s"); err != nil || len(items) != 1 || items[0].Resource != "shared" {
		t.Fatalf("FilteredHeads with prefix: %v %v", items, err)
	}
	entries, fa, err := c.FilteredLog(ctx, "matches", "")
	if err != nil || fa.End != head {
		t.Fatalf("FilteredLog: %v %+v", err, fa)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Resource] = true
	}
	if !seen["derby"] || !seen["shared"] || seen["secret"] || seen["opener"] {
		t.Fatalf("log resources %v", seen)
	}
	if _, err := c.LongPoll(ctx, "matches", head, ""); err == nil {
		t.Fatal("LongPoll followed the filtered form")
	} else if fe, ok := plclient.AsFiltered(err); !ok || fe.GS != fa.GS {
		t.Fatalf("LongPoll: %v", err)
	}
	lp, err := c.FilteredLongPoll(ctx, "matches", fa.GS, head, "")
	if err != nil || lp == nil {
		t.Fatalf("FilteredLongPoll: %+v %v", lp, err)
	}
	// An unrestricted reader's HeadsPrefix.
	ac, _ := plclient.New(w.srv.URL, plclient.WithHTTPClient(&http.Client{Transport: transport}), plclient.WithBearer(w.admin))
	all, err := ac.HeadsPrefix(ctx, "matches", head, "s")
	if err != nil || len(all) != 2 {
		t.Fatalf("HeadsPrefix: %v %v", all, err)
	}
}
