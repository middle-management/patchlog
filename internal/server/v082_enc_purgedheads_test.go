package server

import (
	"strings"
	"testing"
	"time"
)

// v82encFilteredLog is the view and at a partial reader's unfiltered log of
// matches redirects to. A purged namespace's log still redirects, where
// its /heads no longer does (§7.9 Purged namespaces).
func v82encFilteredLog(w *v75s, bearer string) (vid, at string) {
	w.t.Helper()
	r := w.get("/ns/matches/rev/"+w.nsHead("matches", w.admin)+"/log", bearer)
	expect(w.t, r, 302)
	loc := r.H.Get("Location")
	parts := strings.Split(strings.SplitN(loc, "?", 2)[0], "/")
	if len(parts) != 8 || parts[3] != "view" || parts[5] != "at" || parts[7] != "log" {
		w.t.Fatalf("Location %q", loc)
	}
	return parts[4], parts[6]
}

// ACC-8a (SERVICES §7.9 Purged namespaces, SPEC §8.5; scenario 124):
// a partial reader's unfiltered /heads of a covered namespace that is
// purged is 410 purged, with head, at once: no 302 and no Location, and
// since v0.91 whatever the grant, before any read check.
func TestV082PurgedHeadsPartialReader410(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	li := w.li()
	// Before the purge: the 302 to the filtered form, as ever.
	before := w.nsHead("matches", w.admin)
	if r := w.get("/ns/matches/rev/"+before+"/heads", li); r.Code != 302 || !strings.Contains(r.H.Get("Location"), "/ns/matches/view/") {
		t.Fatalf("before the purge: %d %v", r.Code, r.H)
	}
	opg := mint(t, w.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"matches"}, "can": []any{"purge-ns"},
		"exp": w.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	expect(t, w.patchNS("matches", ops(op("add", "/frozen", true)), w.admin), 201)
	expect(t, w.do(req{method: "POST", path: "/ns/matches/purge?force=1", ifMatch: w.nsHead("matches", w.admin), bearer: opg}), 204)
	purgeNS := w.nsHead("matches", w.admin)
	bogus := "1nyv2d2ibcop4nnp4k5niguadz7lvyjad"
	for _, id := range []string{purgeNS, before, bogus} {
		r := w.get("/ns/matches/rev/"+id+"/heads", li)
		expectCode(t, r, 410, "purged")
		if r.Str("head") != purgeNS || r.H.Get("Location") != "" {
			t.Fatalf("/heads at %s: %v %s", id, r.H, r.Body)
		}
		// As the unrestricted reader's 410.
		u := w.get("/ns/matches/rev/"+id+"/heads", w.admin)
		expectCode(t, u, 410, "purged")
		if string(u.Body) != string(r.Body) || u.H.Get("Cache-Control") != r.H.Get("Cache-Control") {
			t.Fatalf("/heads at %s: partial %v %s, unrestricted %v %s", id, r.H, r.Body, u.H, u.Body)
		}
	}
	// Whatever the grant: none, another namespace's, one with a rule on
	// /now, which until v0.91 got the read check's 401 or 403 first.
	other := w.grant(w.k, "user:x", []string{"cat-season"}, []string{"read"})
	now := w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}})
	for name, g := range map[string]string{"no grant": "", "another namespace's": other, "a /now rule": now} {
		if r := w.get("/ns/matches/rev/"+purgeNS+"/heads", g); r.Code != 410 || r.Str("head") != purgeNS || r.H.Get("Location") != "" {
			t.Fatalf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	// The unfiltered log, which redirected until v0.91, is 410 too.
	expectCode(t, w.get("/ns/matches/log", li), 410, "purged")
}
