package core

import (
	"context"
	"testing"
	"time"
)

// V82-02 (v0.82), ACC-8b: a purged covered namespace answers its filtered
// URLs as §8.5 answers their unfiltered forms "once the URL's read check
// passes, its gs included" (SERVICES §B.11.9 Purged namespaces;
// conformance 124, second half).

// v82accessPurgedHeads are the statuses of purged matches' filtered /heads
// for gs under cred: without at, at at, and at an at never recorded.
func v82accessPurgedHeads(w *v75World, gs, at string, cred Credentials) [3]int {
	ctx := context.Background()
	var out [3]int
	out[0] = v75Status(w.e.FilteredCurrent(ctx, "matches", gs, "/heads", cred))
	_, _, err := w.e.FilteredHeads(ctx, "matches", gs, at, "", "", cred)
	out[1] = v75Status(err)
	_, _, err = w.e.FilteredHeads(ctx, "matches", gs, "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", "", cred)
	out[2] = v75Status(err)
	return out
}

// Conformance 124: covered matches is purged. li's grant in Authorization
// at another subject set's /g/{gs}/heads is 403, not 410, with or without
// at; at her own it is 410. An unrestricted reader's grant is 403 at every
// gs, as at a live namespace's filtered URLs (§B.11.9 Partial reader),
// where v0.27.0 answered 410; its 410 is at the unfiltered /heads. A
// cookie is judged as its gs's: 410 at its own, 403 at another, and a
// /ns/matches cookie as that gs's cookie would be.
func TestV082AccessPurgedFilteredHeadsReadCheck(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	li, bo := w.li(), w.catGrant("user:bo", []any{"chiefs"})
	liCookie, liGS := v82accessCookie(t, w, li)
	boGS := v075GS(t, w, bo)
	if liGS == boGS {
		t.Fatal("li and bo share a gs")
	}
	red, st := v76fRedirect(t, w, "matches", liGS, li)
	if red == nil {
		t.Fatalf("before the purge: %d", st)
	}
	// Live: the answers the purged namespace must not improve on.
	if st := v75Status(w.e.FilteredCurrent(ctx, "matches", liGS, "/heads", w.admin)); st != 403 {
		t.Fatalf("live, an unrestricted grant at a filtered URL: %d, want 403", st)
	}
	head := v077Purge(t, w, "matches")
	exp := w.now().Add(10 * time.Minute)
	nsCookie := Credentials{Edge: &EdgeGrant{NS: "matches", Prefix: "/ns/matches", Exp: exp}}
	boCookie := Credentials{Edge: &EdgeGrant{NS: "matches", GS: boGS, Prefix: "/ns/matches/g/" + boGS, Exp: exp}}
	all := func(st int) [3]int { return [3]int{st, st, st} }
	for name, c := range map[string]struct {
		gs   string
		cred Credentials
		want int
	}{
		"li at her own gs":                         {liGS, li, 410},
		"li at another subject set":                {boGS, li, 403},
		"bo at li's":                               {liGS, bo, 403},
		"an unrestricted grant at li's gs":         {liGS, w.admin, 403},
		"an unrestricted grant at another":         {boGS, w.admin, 403},
		"li's cookie at her gs":                    {liGS, liCookie, 410},
		"li's cookie at another":                   {boGS, liCookie, 403},
		"a cookie for a gs nothing is kept for":    {boGS, boCookie, 401},
		"a /ns/matches cookie at li's gs":          {liGS, nsCookie, 410},
		"a /ns/matches cookie at a gs without row": {boGS, nsCookie, 401},
		"no credentials":                           {liGS, Credentials{}, 401},
	} {
		if got := v82accessPurgedHeads(w, c.gs, red.At, c.cred); got != all(c.want) {
			t.Errorf("%s: %v (without at, at an at, at an at not answered), want %d", name, got, c.want)
		}
	}
	// The 410 is §8.5's, with head.
	err := w.e.FilteredCurrent(ctx, "matches", liGS, "/heads", li)
	if e, _ := err.(*Error); e == nil || e.Body["code"] != "purged" || e.Body["head"] != head {
		t.Fatalf("li at her own gs: %v, want purged with head %s", err, head)
	}
	// The unrestricted reader's 410 is at the unfiltered URL.
	if _, err := w.e.NamespaceHeadsPrefix(ctx, "matches", head, "", "", w.admin); v75Status(err) != 410 {
		t.Fatalf("the unfiltered /heads for an unrestricted grant: %v, want 410", err)
	}
}
