package server

import (
	"testing"
	"time"
)

// Cross-package review of v0.75 (§B.11.9): conformance.

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
	gs, at := w.filtered(li)
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
