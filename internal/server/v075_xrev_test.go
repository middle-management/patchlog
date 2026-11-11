package server

import (
	"reflect"
	"testing"
	"time"
)

// Cross-package review of v0.75 (§B.11.9): conformance.

// v75sLoseRead seeds derby, visible to li, and returns li's grant, her gs
// cookie and gs, once her cookie reads derby at the current at.
func v75sLoseRead(t *testing.T, w *v75s) (li string, ck map[string]string, gs string) {
	t.Helper()
	w.put("cat-season", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:editors": []any{"viewer"}}})
	w.put("cat-season", "season", map[string]any{"parents": v75sParents("root")})
	w.put("cat-season", "matches.derby", map[string]any{"parents": v75sParents("season")})
	w.put("matches", "derby", map[string]any{"title": "derby"})
	li = w.li() // roles: reader
	c, gs := w.cookie(li)
	ck = cookieHdr(c)
	_, at := w.filtered(li)
	r := w.do(req{method: "GET", path: "/ns/matches/g/" + gs + "/at/" + at + "/heads", hdr: ck})
	expect(t, r, 200)
	if names := headNames(t, r); !reflect.DeepEqual(names, []string{"derby"}) {
		t.Fatalf("before: %v", names)
	}
	return li, ck, gs
}

// wantCookieRefused checks that gs's cookie ck reads nothing at the
// current at, once its grant li can't read matches.
func wantCookieRefused(t *testing.T, w *v75s, li string, ck map[string]string, gs string) {
	t.Helper()
	if r := w.get("/ns/matches/rev/"+w.nsHead("matches", w.admin)+"/heads", li); r.Code != 403 {
		t.Fatalf("the grant: %d %v", r.Code, r.H.Get("Location"))
	}
	r := w.do(req{method: "GET", path: "/ns/matches/g/" + gs + "/heads", hdr: ck})
	if r.Code == 302 {
		r = w.do(req{method: "GET", path: r.H.Get("Location"), hdr: ck})
	}
	if r.Code != 403 {
		t.Errorf("the cookie, where its grant reads nothing: %d %s", r.Code, r.Body)
	}
}

// TestV075XrevCookieAfterRoleLosesRead (§B.11.9 gs, §A.4, §2.1): li's grant
// reads matches through its role reader; once reader no longer lists
// read, the grant can't read matches (403), and the rules her marker
// digests, of each effective role listing read, differ: her gs cookie is
// 403 too, though folders give her the role viewer, so item 1 still
// passes.
func TestV075XrevCookieAfterRoleLosesRead(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{matches: func(doc map[string]any) {
		doc["roles"].(map[string]any)["viewer"] = map[string]any{"can": []any{"read"}}
	}})
	li, ck, gs := v75sLoseRead(t, w)
	expect(t, w.patchNS("matches", ops(op("replace", "/roles/reader/can", []any{"create"})), w.admin), 201)
	wantCookieRefused(t, w, li, ck, gs)
}

// TestV075XrevCookieAfterKeyLosesRead: likewise once the key that signed
// li's grant no longer lists read (§C.2: a request is allowed only through
// what its blocks, its key's scope and an effective role allow together).
func TestV075XrevCookieAfterKeyLosesRead(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{matches: func(doc map[string]any) {
		doc["roles"].(map[string]any)["viewer"] = map[string]any{"can": []any{"read"}}
	}})
	li, ck, gs := v75sLoseRead(t, w)
	expect(t, w.patchNS("matches", ops(op("replace", "/keys/1/can", []any{"create"})), w.admin), 201)
	wantCookieRefused(t, w, li, ck, gs)
}

// TestV075XrevFilteredHeadsPurgedUnknownAt (§B.11.9 Purged namespaces,
// §8.5): /heads at any revision answers 410 as soon as the read check
// passes, before any other answer to a well-formed request, as the
// unfiltered /heads of a purged namespace does at a revision that isn't
// one: so does the filtered /heads at an at the origin doesn't hold,
// rather than 302 to the current at first. A filtered log range there
// still redirects, a purged range staying readable.
func TestV075XrevFilteredHeadsPurgedUnknownAt(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	li := w.li()
	opg := mint(t, w.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"matches"}, "can": []any{"purge-ns"},
		"exp": w.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	expect(t, w.patchNS("matches", ops(op("add", "/frozen", true)), w.admin), 201)
	expect(t, w.do(req{method: "POST", path: "/ns/matches/purge?force=1", ifMatch: w.nsHead("matches", w.admin), bearer: opg}), 204)
	// Her unfiltered /heads is 410 directly since v0.82 (ACC-8a); the
	// unfiltered log still redirects to her gs.
	expectCode(t, w.get("/ns/matches/rev/"+w.nsHead("matches", w.admin)+"/heads", li), 410, "purged")
	gs, at := v82encFilteredLog(w, li)
	bogus := "1nyv2d2ibcop4nnp4k5niguadz7lvyjad"
	expectCode(t, w.get("/ns/matches/rev/"+bogus+"/heads", w.admin), 410, "purged")
	expectCode(t, w.get("/ns/matches/g/"+gs+"/at/"+bogus+"/heads", li), 410, "purged")
	expectCode(t, w.get("/ns/matches/g/"+gs+"/at/"+at+"/heads", li), 410, "purged")
	if r := w.get("/ns/matches/g/"+gs+"/at/"+bogus+"/log", li); r.Code != 302 {
		t.Errorf("filtered log of a purged namespace at an unknown at: %d", r.Code)
	}
	// The read check still comes first.
	if r := w.get("/ns/matches/g/"+gs+"/at/"+bogus+"/heads", ""); r.Code != 401 {
		t.Errorf("without a grant: %d", r.Code)
	}
}
