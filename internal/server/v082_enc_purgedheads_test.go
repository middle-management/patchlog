package server

import (
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

// v82encFilteredLog is the gs and at a partial reader's unfiltered log of
// matches redirects to. A purged namespace's log still redirects, where
// its /heads no longer does (§B.11.9 Purged namespaces).
func v82encFilteredLog(w *v75s, bearer string) (gs, at string) {
	w.t.Helper()
	r := w.get("/ns/matches/rev/"+w.nsHead("matches", w.admin)+"/log", bearer)
	expect(w.t, r, 302)
	loc := r.H.Get("Location")
	parts := strings.Split(strings.SplitN(loc, "?", 2)[0], "/")
	if len(parts) != 8 || parts[3] != "g" || parts[5] != "at" || parts[7] != "log" {
		w.t.Fatalf("Location %q", loc)
	}
	return parts[4], parts[6]
}

// ACC-8a (SERVICES §B.11.9 Purged namespaces, SPEC §8.5; scenario 124):
// a partial reader's unfiltered /heads of a covered namespace that is
// purged is 410 purged, with head, at once: no 302 and no Location, and
// no at is recorded. The read check comes first: without a grant 401, and
// a grant whose read is refused 403, neither with head. The unfiltered
// log of the purged namespace still redirects.
func TestV082PurgedHeadsPartialReader410(t *testing.T) {
	t.Parallel()
	var path string
	w := newV75s(t, v75sOpts{env: []envOpt{withFileDB(t), func(o *core.Options) { path = o.Path }}})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	li := w.li()
	// Before the purge: the 302 to the filtered form, as ever.
	before := w.nsHead("matches", w.admin)
	if r := w.get("/ns/matches/rev/"+before+"/heads", li); r.Code != 302 || !strings.Contains(r.H.Get("Location"), "/ns/matches/g/") {
		t.Fatalf("before the purge: %d %v", r.Code, r.H)
	}
	opg := mint(t, w.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"matches"}, "can": []any{"purge-ns"},
		"exp": w.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	expect(t, w.patchNS("matches", ops(op("add", "/frozen", true)), w.admin), 201)
	expect(t, w.do(req{method: "POST", path: "/ns/matches/purge?force=1", ifMatch: w.nsHead("matches", w.admin), bearer: opg}), 204)
	purgeNS := w.nsHead("matches", w.admin)
	db, pg := v0261DB(t, path)
	ats := v0261Count(t, db, pg, `SELECT COUNT(*) FROM filtered_ats`)
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
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM filtered_ats`); n != ats {
		t.Fatalf("the 410 recorded an at: %d rows, were %d", n, ats)
	}
	// The read check first.
	if r := w.get("/ns/matches/rev/"+purgeNS+"/heads", ""); r.Code != 401 || r.Obj()["head"] != nil {
		t.Fatalf("without a grant: %d %s", r.Code, r.Body)
	}
	other := w.grant(w.k, "user:x", []string{"cat-season"}, []string{"read"})
	if r := w.get("/ns/matches/rev/"+purgeNS+"/heads", other); r.Code != 403 || r.Obj()["head"] != nil {
		t.Fatalf("a grant of another namespace: %d %s", r.Code, r.Body)
	}
	// A partial reader's grant that fails every read (a block rule on
	// /now, §C.2 item 5): its 403, never the 410.
	now := w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}})
	if r := w.get("/ns/matches/rev/"+purgeNS+"/heads", now); r.Code != 403 || r.Obj()["head"] != nil || r.H.Get("Location") != "" {
		t.Fatalf("a grant with a /now rule: %d %s", r.Code, r.Body)
	}
	// The unfiltered log still redirects, and the filtered /heads it
	// leads to answers the same 410.
	gs, at := v82encFilteredLog(w, li)
	expectCode(t, w.get("/ns/matches/g/"+gs+"/at/"+at+"/heads", li), 410, "purged")
}
