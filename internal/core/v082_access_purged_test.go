package core

import (
	"context"
	"testing"
	"time"
)

// V82-02 (v0.82), ACC-8b: a purged covered namespace answers its filtered
// URLs as §8.5 answers their unfiltered forms "once the URL's read check
// passes, its view included" (SERVICES §7.9 Purged namespaces;
// conformance 124, second half).

// v82accessPurgedHeads are the statuses of purged matches' filtered /heads
// for view under cred: without at, at at, and at an at never recorded.
func v82accessPurgedHeads(w *v75World, vid, at string, cred Credentials) [3]int {
	ctx := context.Background()
	var out [3]int
	out[0] = v75Status(w.e.FilteredCurrent(ctx, "matches", vid, "/heads", cred))
	_, _, err := w.e.FilteredHeads(ctx, "matches", vid, at, "", "", cred)
	out[1] = v75Status(err)
	_, _, err = w.e.FilteredHeads(ctx, "matches", vid, "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", "", cred)
	out[2] = v75Status(err)
	return out
}

// Conformance 124: covered matches is purged. li's grant in Authorization
// at another subject set's /view/{view}/heads is 403, not 410, with or without
// at; at her own it is 410. An unrestricted reader's grant is 403 at every
// view, as at a live namespace's filtered URLs (§7.9 Partial reader),
// where v0.27.0 answered 410; its 410 is at the unfiltered /heads. A
// cookie is judged as its view's: 410 at its own, 403 at another, and a
// /ns/matches cookie as that view's cookie would be.
func TestV082AccessPurgedFilteredHeadsReadCheck(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	li, bo := w.li(), w.bo()
	liCookie, liView := v82accessCookie(t, w, li)
	boView := v075ViewID(t, w, bo)
	if liView == boView {
		t.Fatal("li and bo share a vid")
	}
	red, st := v76fRedirect(t, w, "matches", liView, li)
	if red == nil {
		t.Fatalf("before the purge: %d", st)
	}
	// Live: the answers the purged namespace must not improve on.
	if st := v75Status(w.e.FilteredCurrent(ctx, "matches", liView, "/heads", w.admin)); st != 403 {
		t.Fatalf("live, an unrestricted grant at a filtered URL: %d, want 403", st)
	}
	head := v077Purge(t, w, "matches")
	exp := w.now().Add(10 * time.Minute)
	nsCookie := Credentials{Edge: &EdgeGrant{NS: "matches", Prefix: "/ns/matches", Exp: exp}}
	boCookie := Credentials{Edge: &EdgeGrant{NS: "matches", View: boView, Prefix: "/ns/matches/view/" + boView, Exp: exp}}
	all := func(st int) [3]int { return [3]int{st, st, st} }
	for name, c := range map[string]struct {
		vid  string
		cred Credentials
		want int
	}{
		"li at her own vid":                         {liView, li, 410},
		"li at another subject set":                 {boView, li, 403},
		"bo at li's":                                {liView, bo, 403},
		"an unrestricted grant at li's vid":         {liView, w.admin, 403},
		"an unrestricted grant at another":          {boView, w.admin, 403},
		"li's cookie at her vid":                    {liView, liCookie, 410},
		"li's cookie at another":                    {boView, liCookie, 403},
		"a cookie for a vid nothing is kept for":    {boView, boCookie, 401},
		"a /ns/matches cookie at li's vid":          {liView, nsCookie, 410},
		"a /ns/matches cookie at a vid without row": {boView, nsCookie, 410},
		"no credentials":                            {liView, Credentials{}, 401},
	} {
		if got := v82accessPurgedHeads(w, c.vid, red.At, c.cred); got != all(c.want) {
			t.Errorf("%s: %v (without at, at an at, at an at not answered), want %d", name, got, c.want)
		}
	}
	// The 410 is §8.5's, with head.
	err := w.e.FilteredCurrent(ctx, "matches", liView, "/heads", li)
	if e, _ := err.(*Error); e == nil || e.Body["code"] != "purged" || e.Body["head"] != head {
		t.Fatalf("li at her own vid: %v, want purged with head %s", err, head)
	}
	// The unrestricted reader's 410 is at the unfiltered URL.
	if _, err := w.e.NamespaceHeadsPrefix(ctx, "matches", head, "", "", w.admin); v75Status(err) != 410 {
		t.Fatalf("the unfiltered /heads for an unrestricted grant: %v, want 410", err)
	}
}
