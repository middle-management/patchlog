package server

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.90 "Filtering a namespace" (§7.9 Where, §7 step 1, §9; HTTP-83,
// scenario 95): in a public namespace a grant with read rules is a
// filter, taken only under its view prefix. There a partial reader's
// grant reads filtered, a request with neither a grant nor a cookie is
// 401 and another view 403, and every answer is cached as a private
// namespace's: Cache-Control private, CDN-Cache-Control no-store with a
// grant in Authorization, edge lifetimes for a cookie the verifying edge
// verified. Every other read ignores the grant, answering as to an
// anonymous request, and none redirects to the view; a hidden revision
// stays hidden under the prefix even once the public read cache holds it.
func TestV090PublicViewRouteTable(t *testing.T) {
	t.Parallel()
	v, err := edge.New([]byte("s3cret"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	w := newV75s(t, v75sOpts{srv: []Option{WithEdge(v)}, matches: func(doc map[string]any) { doc["read"] = "public" }})
	reader := w.grant(w.k, "user:r", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"all": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^[a-m]"}}, v87TeamA}}}})
	data := []byte("blob")
	bid := w.upload("matches", "doc", "text/plain", data, w.admin)
	ref := map[string]any{"$blob": bid, "type": "text/plain", "size": float64(len(data))}
	visible := w.v87Doc("matches", "doc", map[string]any{"team": "a", "file": ref})
	hid := w.v87Doc("matches", "hid", map[string]any{"team": "b", "mark": "HIDDEN-DOC"})
	w.v87Doc("matches", "zzz-name", map[string]any{"team": "a", "mark": "HIDDEN-NAME"})
	nsHead := etagOf(w.get("/ns/matches", w.admin))
	gid := ""
	for _, e := range w.nsLog("matches", w.admin) {
		if g, ok := e["grant"].(map[string]any); ok {
			gid, _ = g["id"].(string)
		}
	}
	// No redirect tells the reader its view: the exchange does (§C.5.2).
	ck, view := w.cookie(reader)
	base := "/ns/matches/view/" + view

	// The unfiltered URLs ignore the grant: public, unfiltered, no 302.
	r := w.get("/ns/matches/rev/"+nsHead+"/heads", reader)
	expect(t, r, 200)
	if !strings.Contains(string(r.Body), `"hid"`) || r.H.Get("Cache-Control") != ccImmutable {
		t.Fatalf("the unfiltered /heads to the reader: %v %s", r.H, r.Body)
	}
	expect(t, w.get("/r/matches/hid", reader), 302)
	// The hidden revision, read anonymously, is in the public read cache.
	expect(t, w.get("/r/matches/hid/rev/"+hid), 200)
	expect(t, w.get("/r/matches/hid/rev/"+hid, reader), 200)

	// Under the prefix: filtered, private.
	private := func(what string, r *resp) {
		t.Helper()
		if cc := r.H.Get("Cache-Control"); strings.Contains(cc, "public") || cc == "" {
			t.Errorf("%s: Cache-Control %q, want a private namespace's", what, cc)
		}
		if cdn := r.H.Get("CDN-Cache-Control"); cdn != "no-store" && r.H.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: CDN-Cache-Control %q, want no-store with a grant in Authorization", what, cdn)
		}
	}
	r = w.get(base+"/at/"+nsHead+"/heads", reader)
	expect(t, r, 200)
	private("the view's /heads", r)
	if rows := r.Obj()["heads"].([]any); len(rows) != 1 || rows[0].(map[string]any)["resource"] != "doc" {
		t.Fatalf("the view's /heads: %s", r.Body)
	}
	expectCode(t, w.get(base+"/at/"+nsHead+"/heads"), 401, "unauthenticated")
	expect(t, w.get("/ns/matches/view/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/at/"+nsHead+"/heads", reader), 403)
	// The hidden revision under the prefix: a read-rule failure, the
	// public read cache notwithstanding.
	r = w.get(base+"/r/hid/rev/"+hid, reader)
	if r.Code != 404 || strings.Contains(string(r.Body), "HIDDEN") {
		t.Fatalf("a hidden revision under the view: %d %s", r.Code, r.Body)
	}
	private("a hidden revision under the view", r)
	r = w.get(base+"/r/doc/rev/"+visible, reader)
	expect(t, r, 200)
	private("a visible revision under the view", r)
	// Behind a verifying edge, the reader's cookie: edge lifetimes, as
	// for a private namespace (§9).
	h := cookieHdr(ck)
	maps.Copy(h, map[string]string{edge.DefaultHeader: "s3cret", edge.DefaultPrefixHeader: base})
	r = w.do(req{method: "GET", path: base + "/at/" + nsHead + "/heads", hdr: h})
	expect(t, r, 200)
	if r.H.Get("Cache-Control") != "private, max-age=300" || r.H.Get("CDN-Cache-Control") != "max-age=86400, s-maxage=31536000, immutable" {
		t.Fatalf("the cookie's read the edge verified: %v", r.H)
	}

	// Every read route.
	sub := func(p string) string {
		return strings.NewReplacer("{ns}", "matches", "{name}", "doc", "{id}", visible, "{bid}", bid, "{e}", "1", "{view}", view,
			"{at}", nsHead, "{gesture}", "aaaaaaaaaaaaaaaaaaaaaaaaaa", "{gid}", gid, "{$}", "").Replace(p)
	}
	underView := map[string][]int{
		"/ns/{ns}/view/{view}/at/{at}/heads":             {200},
		"/ns/{ns}/view/{view}/at/{at}/log":               {200},
		"/ns/{ns}/view/{view}/heads":                     {302},
		"/ns/{ns}/view/{view}/log":                       {302},
		"/ns/{ns}/view/{view}/events":                    {200},
		"/ns/{ns}/view/{view}/r/{name}/rev/{id}":         {200},
		"/ns/{ns}/view/{view}/r/{name}/rev/{id}/raw":     {404},
		"/ns/{ns}/view/{view}/r/{name}/blob/{bid}":       {200},
		"/ns/{ns}/view/{view}/r/{name}/blob/{bid}/e/{e}": {404},
	}
	// These take the grant in a public namespace too (§7 step 1).
	takesGrant := []string{"/ns", "/ns/{ns}/principal"}
	for _, route := range v87Routes(t) {
		path := sub(route)
		switch {
		case strings.HasSuffix(route, "/events") && strings.HasPrefix(route, "/r/"):
			path += "?since=" + visible
		case strings.HasSuffix(route, "/events"):
			path += "?since=" + nsHead
		case route == "/ns/{ns}/log", strings.HasSuffix(route, "/{ns}/{name}/log"):
			path += "?live=long-poll"
		}
		r := w.v87Get(path, reader)
		if codes, ok := underView[route]; ok {
			if !slices.Contains(codes, r.Code) {
				t.Errorf("%s: %d %s, want %v", route, r.Code, r.Body, codes)
				continue
			}
			if r.Code == 302 && !strings.HasPrefix(r.H.Get("Location"), base+"/") {
				t.Errorf("%s: Location %q, want under %s", route, r.H.Get("Location"), base)
			}
			if !strings.HasSuffix(route, "/events") {
				private(route, r)
			}
			for _, leak := range []string{"HIDDEN-DOC", "HIDDEN-NAME", "zzz-name", `"hid"`} {
				if strings.Contains(string(r.Body), leak) {
					t.Errorf("%s: leaks %s: %s", route, leak, r.Body)
				}
			}
			continue
		}
		if strings.Contains(route, "{view}") {
			t.Errorf("route %s under a view has no row: classify it", route)
			continue
		}
		if strings.Contains(r.H.Get("Location"), "/view/") {
			t.Errorf("%s: redirects the reader to its view: %s", route, r.H.Get("Location"))
		}
		if slices.Contains(takesGrant, route) || route == core.DefaultJWKSPath {
			continue
		}
		if anon := w.v87Get(path, ""); anon.Code != r.Code {
			t.Errorf("%s: %d to the reader, %d anonymously: the grant isn't ignored", route, r.Code, anon.Code)
		}
	}
}

// v0.90 (§7.4, §8.3 Limits of purge, HTTP-82, scenario 97): at E3 a head
// entry carries no schema, the server never seeing the document; and a
// purge keeps the schema of the head entries before it.
func TestV090SchemaE3AndPurge(t *testing.T) {
	t.Parallel()
	e, _ := newE3Env(t)
	e.mkNS("e3", e2eDoc(map[string]any{"read": "public"}))
	k := seal.NewKey()
	e.e3Write(k, "e3", "derby", "", addRoot(map[string]any{"$schema": "/r/schemas/match/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "n": 1.0}))
	for _, en := range e.nsLog("e3") {
		if _, ok := en["schema"]; ok {
			t.Fatalf("an E3 entry with schema: %v", en)
		}
	}

	e.mkNS("plain", map[string]any{"read": "public"})
	s := e.create("plain", "s", map[string]any{"$schema": dialect, "type": "object"})
	ref := "/r/plain/s/rev/" + s
	d := e.create("plain", "derby", map[string]any{"$schema": ref, "n": 1.0})
	schemaOf := func() any {
		for _, en := range e.nsLog("plain") {
			if en["kind"] == "head" && en["resource"] == "derby" {
				return en["schema"]
			}
		}
		return nil
	}
	if got := schemaOf(); got != ref {
		t.Fatalf("derby's head entry: schema %v, want %s", got, ref)
	}
	expect(t, e.purge("plain", "derby", d, "admin"), 204)
	if got := schemaOf(); got != ref {
		t.Fatalf("derby's head entry once purged: schema %v, want %s", got, ref)
	}
}
