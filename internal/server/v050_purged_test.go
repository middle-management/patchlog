package server

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

// purgeNSAs freezes ns and purges it under bearer, returning the purge-ns
// entry's ns_id.
func (e *tenv) purgeNSAs(ns, bearer string) string {
	e.t.Helper()
	expect(e.t, e.patchNS(ns, ops(op("add", "/frozen", true)), bearer), 201)
	r := e.do(req{method: "POST", path: "/ns/" + ns + "/purge", ifMatch: e.nsHead(ns, bearer), bearer: bearer})
	expect(e.t, r, 204)
	// The purge-ns entry's id, all the namespace keeps but its name (§5).
	return r.H.Get("X-Namespace-Revision")
}

// purging serves A through a proxy that answers 410 purged, with head, for
// paths containing match.
func purging(t *testing.T, a *tenv, match, head string) string {
	t.Helper()
	u, err := url.Parse(a.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, match) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(410)
			w.Write([]byte(`{"code":"purged","head":"` + head + `"}`))
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(p.Close)
	return p.URL
}

// v0.50 §8.5, as v0.91 answers it: a purged namespace's URLs answer 410
// before any other answer to a well-formed request, whatever the grant: 404
// for an unknown id, not_offered for the gestures listing of a sealed
// namespace, and the refusals of a grant whose rules refuse the read, which
// until v0.91 came first. A malformed request still gets its 400.
func TestV050PurgedReadCheck(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	a0 := e.create("sec", "a", map[string]any{}, f.adminG)
	e.create("sec", "b", map[string]any{}, f.adminG)
	gid := grantIDOf(t, f.adminG)
	at := e.nsHead("sec", f.adminG)
	head := e.purgeNSAs("sec", f.adminG)
	unknown := hashID(t, "", nil)
	readOnly := func(name string) string {
		return e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{
			map[string]any{"op": "test", "path": "/resource", "value": name}}})
	}
	onlyA, onlyB := readOnly("a"), readOnly("b")
	appendOnly := e.grant(f.issuer, "user:w", []string{"sec"}, []string{"append"})

	for _, c := range []struct {
		path, bearer string
		code         int // 0: 410 purged
	}{
		// Resource URLs: read on that resource.
		{"/r/sec/a", onlyB, 0},
		{"/r/sec/a", onlyA, 0},
		{"/r/sec/a/rev/" + a0, onlyB, 0},
		{"/r/sec/a/rev/" + a0, onlyA, 0},
		{"/r/sec/a/rev/" + unknown, onlyA, 0},
		{"/r/sec/a/rev/" + a0 + "/log", onlyA, 0},
		// /heads and grants: unrestricted read (403 otherwise, v0.74), then
		// 410 for unknown ids too.
		{"/ns/sec/rev/" + at + "/heads", onlyA, 0},
		{"/ns/sec/rev/" + at + "/heads", f.adminG, 0},
		{"/ns/sec/rev/" + unknown + "/heads", f.adminG, 0},
		{"/ns/sec/grants/" + gid, onlyA, 0},
		{"/ns/sec/grants/" + gid, f.adminG, 0},
		{"/ns/sec/grants/" + grantIDOf(t, appendOnly), f.adminG, 0},
		// The gestures listing: any read.
		{"/ns/sec/gestures/" + gA, "", 0},
		{"/ns/sec/gestures/" + gA, appendOnly, 0},
		{"/ns/sec/gestures/" + gA, onlyA, 0},
		// Not well-formed: the request's shape comes first.
		{"/r/sec/a?bogus=1", onlyA, 400},
	} {
		r := e.get(c.path, c.bearer)
		if c.code == 0 {
			if r.Code != 410 || r.Str("code") != "purged" || r.Str("head") != head || r.Obj()["ns"] != nil {
				t.Errorf("%s: %d %s, want 410 purged with head %s", c.path, r.Code, r.Body, head)
			}
		} else if r.Code != c.code {
			t.Errorf("%s: %d %s, want %d", c.path, r.Code, r.Body, c.code)
		}
	}

	// A sealed namespace's gestures listing, which a live one doesn't
	// offer: 410 for a grant whose rules read one resource only.
	s := newSealedAuthEnv(t)
	k := newKey("admin")
	s.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	admin := s.grant(k, "user:root", []string{"s"}, allVerbs)
	one := s.grant(k, "user:r", []string{"s"}, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	expectCode(t, s.get("/ns/s/gestures/"+gA, one), 404, "not_offered")
	sh := s.purgeNSAs("s", admin)
	expectPurged(t, s.get("/ns/s/gestures/"+gA, one), sh)
}
