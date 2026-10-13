package tree_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

// TestMinAlwaysRedirects (§A.5, §B.5): a listing request with min is never
// answered 200. An at URL whose listing already includes every min (the
// current at, or a kept one whose checkpoints show it) redirects to itself
// without min; anything else, once min is reached, to the current at.
func TestMinAlwaysRedirects(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	early := must(w.c.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": parents()})).NSID
	w.folder(t, "season", "Season 2026", "root@a0")
	w.content(t, "matches", "derby")
	w.place(t, "matches.derby", "season@a1")
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	at, catAt, mAt := x.s.At(), x.s.Checkpoint("cat"), x.s.Checkpoint("matches")
	loc := "/cat/at/" + at + "/roots"

	// The current at includes every min the wait reached, bare ones too.
	for _, m := range []string{"cat:" + catAt, catAt, "matches:" + mAt, "cat:" + early + "&min=matches:" + mAt} {
		r := x.raw(loc+"?min="+m, "")
		if r.status != 302 || r.header.Get("Location") != loc || r.header.Get("Cache-Control") != "public, max-age=0, s-maxage=1, stale-while-revalidate=5" {
			t.Errorf("current at, min=%s: %d %s", m, r.status, r.header.Get("Location"))
		}
	}
	if r := x.raw(loc, ""); r.status != 200 || r.body["at"] != at {
		t.Fatalf("at: %d %v", r.status, r.body)
	}

	// The checkpoint moves on. The kept at still includes the catalog's
	// and matches' checkpoints it is over, and ns_ids before them; a min
	// past it goes to the current at, and so does a bare ns_id, whose
	// namespace an older at can't be judged by.
	next := must(w.c.CreateDoc(ctx, "cat", "extra", map[string]any{"title": "Extra", "parents": parents()})).NSID
	x.caughtUp("cat")
	cur := x.s.At()
	curLoc := "/cat/at/" + cur + "/roots"
	for m, want := range map[string]string{
		"cat:" + catAt:                         loc,
		"cat:" + early:                         loc,
		"matches:" + mAt:                       loc,
		"cat:" + catAt + "&min=matches:" + mAt: loc,
		catAt:                                  curLoc,
		"cat:" + next:                          curLoc,
		"cat:" + early + "&min=cat:" + next:    curLoc,
	} {
		r := x.raw(loc+"?min="+m, "")
		if r.status != 302 || r.header.Get("Location") != want {
			t.Errorf("kept at, min=%s: %d %s, want %s", m, r.status, r.header.Get("Location"), want)
		}
	}
	if r := x.raw(loc, ""); r.status != 200 || r.body["at"] != at || names(r.body["roots"]) != "root" {
		t.Errorf("kept at: %d %v", r.status, r.body)
	}
	if r := x.raw(curLoc, ""); r.status != 200 || names(r.body["roots"]) != "extra,root" {
		t.Errorf("current at: %d %v", r.status, r.body)
	}
	// The head pointer with min: one hop to an at URL without it.
	if r := x.raw("/cat/roots?min=cat:"+next, ""); r.status != 302 || r.header.Get("Location") != curLoc {
		t.Errorf("pointer with min: %d %s", r.status, r.header.Get("Location"))
	}
	// A listing nobody asked for at the older at isn't kept: with a min it
	// includes, it goes to the current at.
	if r := x.raw("/cat/at/"+at+"/children?of=season&min=cat:"+catAt, ""); r.status != 302 || r.header.Get("Location") != "/cat/at/"+cur+"/children?of=season" {
		t.Errorf("not kept, with min: %d %s", r.status, r.header.Get("Location"))
	}
}

// TestCanonicalURLs (§A.5, §B.5): listings are answered only at the
// canonical form of their query, and other forms are redirected to it; a
// children listing's next is in that form, so it answers at once.
func TestCanonicalURLs(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed(t)
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	base := "/cat/at/" + x.s.At()
	for _, c := range []struct{ name, path, canon string }{
		{"names out of order", "/children?of=season&limit=2", "/children?limit=2&of=season"},
		{"slashes in the clear", "/where?item=/r/matches/derby", "/where?item=%2Fr%2Fmatches%2Fderby"},
		{"lowercase hex", "/where?item=%2fr%2fmatches%2fderby", "/where?item=%2Fr%2Fmatches%2Fderby"},
		{"empty query", "/roots?", "/roots"},
	} {
		r := x.raw(base+c.path, "")
		if r.status != 302 || r.header.Get("Location") != base+c.canon {
			t.Errorf("%s: %d %s, want %s", c.name, r.status, r.header.Get("Location"), base+c.canon)
			continue
		}
		if r := x.raw(base+c.canon, ""); r.status != 200 {
			t.Errorf("%s: canonical form %d %v", c.name, r.status, r.body)
		}
	}
	var pages []string
	r := x.raw(base+"/children?limit=1&of=season", "")
	for range 4 {
		if r.status != 200 {
			t.Fatalf("children after %v: %d %s", pages, r.status, r.header.Get("Location"))
		}
		pages = append(pages, names(r.body["children"]))
		next, _ := r.body["next"].(string)
		if next == "" {
			break
		}
		r = x.raw(base+"/children"+next, "")
	}
	if len(pages) < 2 {
		t.Errorf("children pages %v", pages)
	}
}

// TestMinRedirectAnswered (§A.4 "Bounded redirects", §B.5): the current at
// with a min it includes redirects to itself without min, with the listing
// computed and kept there first, so the redirect is answered after the
// checkpoint moves on before it is followed.
func TestMinRedirectAnswered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	at, catAt := x.s.At(), x.s.Checkpoint("cat")
	for i, p := range []string{"/roots?min=cat:" + catAt, "/children?min=" + catAt + "&of=season"} {
		r := x.raw("/cat/at/"+at+p, "")
		loc := r.header.Get("Location")
		if r.status != 302 || !strings.HasPrefix(loc, "/cat/at/"+at+"/") || strings.Contains(loc, "min=") {
			t.Fatalf("%s: %d %s", p, r.status, loc)
		}
		must(w.c.CreateDoc(ctx, "cat", "extra"+strconv.Itoa(i), map[string]any{"title": "Extra", "parents": parents()}))
		x.caughtUp("cat")
		if r := x.raw(loc, ""); r.status != 200 || r.body["at"] != at {
			t.Errorf("%s: redirect target after the checkpoint moved: %d %s", p, r.status, r.header.Get("Location"))
		}
		at, catAt = x.s.At(), x.s.Checkpoint("cat")
	}
}

// TestRepeatedParams (§A.5): every listing parameter but min is
// single-valued, and the canonical form sorts a repeated one's values, so
// a repeat would change what a redirect means: it is refused, on the head
// pointer and on an at URL alike.
func TestRepeatedParams(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed(t)
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	at := x.s.At()
	for _, c := range []struct{ param, path string }{
		{"of", "/children?of=season&of=root"},
		{"item", "/where?item=/r/matches/derby&item=/r/matches/opener"},
		{"limit", "/children?of=season&limit=1&limit=2"},
		{"name", "/children?of=season&name=a&name=b"},
		{"after", "/children?of=season&after=a0&after=a1"},
		{"unordered", "/children?of=season&unordered=1&unordered=0"},
		{"depth", "/subtree?of=season&depth=1&depth=2"},
	} {
		for _, p := range []string{"/cat" + c.path, "/cat/at/" + at + c.path} {
			r := x.raw(p, "")
			if msg, _ := r.body["message"].(string); r.status != 400 || r.body["code"] != "bad_input" || !strings.Contains(msg, c.param) {
				t.Errorf("%s: %d %v", p, r.status, r.body)
			}
		}
	}
	// min is repeatable.
	if r := x.raw("/cat/at/"+at+"/roots?min=cat:"+x.s.Checkpoint("cat")+"&min=matches:"+x.s.Checkpoint("matches"), ""); r.status != 302 {
		t.Errorf("repeated min: %d %v", r.status, r.body)
	}
}
