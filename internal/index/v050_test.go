package index_test

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// TestMinAlwaysRedirects (§A.5): a request with min is never answered 200.
// An at URL whose result already includes every min redirects to itself
// without min; anything else waits for min and redirects to the current
// checkpoint, without min, or answers 503 behind if min isn't reached in
// time. A min of another followed namespace is never included in a result
// of one namespace.
func TestMinAlwaysRedirects(t *testing.T) {
	t.Parallel()
	w := setup(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches", "schemas"}, minWait: 300 * time.Millisecond})
	first := w.doc(t, "derby", w.match, map[string]any{"title": "The Derby"}).NSID
	w.doc(t, "cup", w.match, map[string]any{"title": "Cup final"})
	at := s.caughtUp("matches")
	schemasAt := s.caughtUp("schemas")
	q := "?q=derby"
	loc := "/matches/at/" + at + q
	if r := s.raw("/matches"+q, ""); r.status != 302 || r.header.Get("Location") != loc {
		t.Fatalf("pointer: %d %s", r.status, r.header.Get("Location"))
	}

	// The current at includes its own ns_id and every one before it.
	for _, m := range []string{at, "matches:" + at, first, "matches:" + first} {
		r := s.raw(loc+"&min="+url.QueryEscape(m), "")
		if r.status != 302 || r.header.Get("Location") != loc || r.header.Get("Cache-Control") != "public, max-age=0, s-maxage=1, stale-while-revalidate=5" {
			t.Errorf("current at, min=%s: %d %s %v", m, r.status, r.header.Get("Location"), r.header)
		}
	}
	if r := s.raw(loc, ""); r.status != 200 || r.body["at"] != at {
		t.Fatalf("at: %d %v", r.status, r.body)
	}

	// The checkpoint moves on: the kept at still includes its mins, and
	// redirects to itself; a min past it, or one of another namespace,
	// goes to the current checkpoint.
	rematch := w.doc(t, "rematch", w.match, map[string]any{"title": "Derby rematch"}).NSID
	cur := s.caughtUp("matches")
	curLoc := "/matches/at/" + cur + q
	for m, want := range map[string]string{
		"matches:" + first:     loc,
		at:                     loc,
		rematch:                curLoc,
		"matches:" + rematch:   curLoc,
		"schemas:" + schemasAt: curLoc,
		first + "&min=" + at:   loc,
		first + "&min=" + cur:  curLoc,
	} {
		r := s.raw(loc+"&min="+m, "")
		if r.status != 302 || r.header.Get("Location") != want {
			t.Errorf("kept at, min=%s: %d %s, want %s", m, r.status, r.header.Get("Location"), want)
		}
	}
	if r := s.raw(loc, ""); r.status != 200 || r.body["at"] != at || strings.Join(resources(r.body), ",") != "derby" {
		t.Errorf("kept at: %d %v", r.status, r.body)
	}
	// The head pointer with min goes to an at URL without it in one hop,
	// which answers.
	if r := s.raw("/matches"+q+"&min="+rematch, ""); r.status != 302 || r.header.Get("Location") != curLoc {
		t.Errorf("pointer with min: %d %s", r.status, r.header.Get("Location"))
	}
	if r := s.raw(curLoc, ""); r.status != 200 || strings.Join(resources(r.body), ",") != "derby,rematch" {
		t.Errorf("current at: %d %v", r.status, r.body)
	}

	// An at nobody asked for, with a min it includes, isn't kept: it goes
	// to the current checkpoint.
	if r := s.raw("/matches/at/"+at+"?q=cup&min="+first, ""); r.status != 302 || r.header.Get("Location") != "/matches/at/"+cur+"?q=cup" {
		t.Errorf("not kept, with min: %d %s", r.status, r.header.Get("Location"))
	}

	// A min never reached: 503 behind with Retry-After, on the head
	// pointer and on an at URL alike (schemas' ns_id isn't in matches'
	// chain).
	for _, p := range []string{"/matches" + q + "&min=" + schemasAt, curLoc + "&min=" + schemasAt} {
		r := s.raw(p, "")
		if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") == "" || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v %v", p, r.status, r.body, r.header)
		}
	}
}

// TestMinAlwaysRedirectsPrivate (§A.5): the same under a subject set's URL
// space, which the redirect keeps.
func TestMinAlwaysRedirectsPrivate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec",
		map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}))
	root := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "create"})))
	wr := must(root.CreateDoc(ctx, "sec", "a", map[string]any{"title": "secret"}))
	x := startSvc(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, untyped: true, now: s.Now})
	at := x.caughtUp("sec")
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"sec"}, []string{"read"})
	b := x.search("/sec?limit=5", bob)
	if b["at"] != at {
		t.Fatalf("result at %v, want %s", b["at"], at)
	}
	r := x.raw("/sec?limit=5", bob)
	atLoc := r.header.Get("Location")
	if !strings.HasPrefix(atLoc, "/sec/g/") || !strings.HasSuffix(atLoc, "/at/"+at+"?limit=5") {
		t.Fatalf("at URL %s", atLoc)
	}
	// From another URL space too (the anonymous at URL), and from the
	// pointer, min goes straight to the reader's own at URL, without min.
	for _, p := range []string{atLoc + "&min=" + wr.NSID, "/sec?limit=5&min=sec:" + wr.NSID, "/sec/at/" + at + "?limit=5&min=" + wr.NSID, "/sec?limit=5&min=" + wr.NSID} {
		r := x.raw(p, bob)
		if r.status != 302 || r.header.Get("Location") != atLoc || r.header.Get("Cache-Control") != "private, no-cache" {
			t.Errorf("%s: %d %s %v", p, r.status, r.header.Get("Location"), r.header)
		}
	}
}

// TestMinRedirectAnswered (§A.4 "Bounded redirects", §A.5): the current
// at with a min it includes redirects to itself without min, with the
// result computed and kept there first, so the redirect is answered after
// the checkpoint moves on before it is followed.
func TestMinRedirectAnswered(t *testing.T) {
	t.Parallel()
	w := setup(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}})
	first := w.doc(t, "derby", w.match, map[string]any{"title": "The Derby"}).NSID
	for i, m := range []string{"", "matches:" + first} {
		at := s.caughtUp("matches")
		if m == "" {
			m = at
		}
		q := "?limit=" + string(rune('1'+i)) + "&q=derby"
		loc := "/matches/at/" + at + q
		r := s.raw(loc+"&min="+url.QueryEscape(m), "")
		if r.status != 302 || r.header.Get("Location") != loc {
			t.Fatalf("min=%s: %d %s, want %s", m, r.status, r.header.Get("Location"), loc)
		}
		w.doc(t, "derby"+string(rune('a'+i)), w.match, map[string]any{"title": "Derby"})
		if cur := s.caughtUp("matches"); cur == at {
			t.Fatal("the checkpoint didn't move")
		}
		if r := s.raw(loc, ""); r.status != 200 || r.body["at"] != at {
			t.Errorf("min=%s: redirect target after the checkpoint moved: %d %s", m, r.status, r.header.Get("Location"))
		}
	}
}

// logSince counts namespace-log requests whose since is id.
type logSince struct {
	id string
	rt http.RoundTripper
	n  atomic.Int32
}

func (f *logSince) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/log") && strings.Contains(r.URL.RawQuery, f.id) {
		f.n.Add(1)
	}
	return f.rt.RoundTrip(r)
}

// TestMinJudgedAfterWait (§A.5): a min the index hasn't reached is waited
// for before the core's log is asked anything about it, so an unreached
// min costs the wait's own one check, not more calls ahead of it.
func TestMinJudgedAfterWait(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.doc(t, "derby", w.match, map[string]any{"title": "The Derby"})
	schemasAt := must(w.c.NSHead(context.Background(), "schemas")).ID
	ls := &logSince{id: schemasAt, rt: transport}
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, minWait: 100 * time.Millisecond, hc: &http.Client{Transport: ls}})
	at := s.caughtUp("matches")
	if r := s.raw("/matches/at/"+at+"?q=derby&min="+schemasAt, ""); r.status != 503 || r.body["code"] != "behind" {
		t.Fatalf("unreached min: %d %v", r.status, r.body)
	}
	if n := ls.n.Load(); n != 1 {
		t.Errorf("%d namespace-log calls for an unreached min, want 1", n)
	}
}

// TestCanonicalURLs (§A.5): redirects name the query in one form, names
// and then values sorted bytewise and everything but ALPHA, DIGIT and
// -._~ percent-encoded in uppercase hex; an at URL in any other form is
// redirected to it, and a page after next, in it, answers at once.
// A multi-key sort is one parameter with comma-separated keys: a repeated
// sort is 400, since the canonical form sorts repeated values.
func TestCanonicalURLs(t *testing.T) {
	t.Parallel()
	w := setup(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}})
	w.doc(t, "a", w.match, map[string]any{"title": "The Derby", "attendance": 1, "kickoff": "2026-10-04T10:00:00Z"})
	w.doc(t, "b", w.match, map[string]any{"title": "Derby day", "attendance": 1, "kickoff": "2026-10-04T09:00:00Z"})
	w.doc(t, "c", w.match, map[string]any{"title": "Cup", "attendance": 2, "kickoff": "2026-10-04T08:00:00Z"})
	at := s.caughtUp("matches")
	base := "/matches/at/" + at
	schema := url.QueryEscape(w.match)
	for _, c := range []struct{ name, query, canon string }{
		{"names out of order", "?q=derby&limit=5", "?limit=5&q=derby"},
		{"space as +", "?q=the+derby", "?q=the%20derby"},
		{"lowercase hex", "?q=the%2bderby", "?q=the%2Bderby"},
		{"slashes in the clear", "?schema=" + w.match, "?schema=" + schema},
		// v0.73: counts is one value, no longer repeatable (§A.4); facet
		// values are.
		{"values out of order", "?facet[/status]=planned&facet[/status]=done", "?facet%5B%2Fstatus%5D=done&facet%5B%2Fstatus%5D=planned"},
		{"empty query", "?", ""},
	} {
		r := s.raw(base+c.query, "")
		if r.status != 302 || r.header.Get("Location") != base+c.canon {
			t.Errorf("%s: %d %s, want %s", c.name, r.status, r.header.Get("Location"), base+c.canon)
			continue
		}
		if r := s.raw(base+c.canon, ""); r.status != 200 {
			t.Errorf("%s: canonical form %d %v", c.name, r.status, r.body)
		}
		// The head pointer redirects to the canonical form too.
		if r := s.raw("/matches"+c.query, ""); r.status != 302 || r.header.Get("Location") != base+c.canon {
			t.Errorf("%s: pointer %d %s", c.name, r.status, r.header.Get("Location"))
		}
	}

	// next is the after of the following page (v0.73, §A.4), whose
	// canonical URL answers without a redirect.
	b := s.search("/matches?schema="+schema+"&limit=1", "")
	for range 3 {
		next, _ := b["next"].(string)
		if next == "" {
			break
		}
		u := base + "?after=" + url.QueryEscape(next) + "&limit=1&schema=" + schema
		r := s.raw(u, "")
		if r.status != 200 {
			t.Fatalf("next %s: %d %s", u, r.status, r.header.Get("Location"))
		}
		b = r.body
	}

	// Multi-key sort, comma-separated; repeated, it is refused.
	s.expect("/matches?sort=-/attendance,/kickoff", "c", "b", "a")
	s.expect("/matches?sort=/attendance,-/kickoff", "a", "b", "c")
	for _, p := range []string{"/matches?sort=-/attendance&sort=/kickoff", base + "?sort=%2Fkickoff&sort=-%2Fattendance"} {
		r := s.raw(p, "")
		if msg, _ := r.body["message"].(string); r.status != 400 || r.body["code"] != "bad_input" || !strings.Contains(msg, "commas") {
			t.Errorf("%s: %d %v", p, r.status, r.body)
		}
	}
}

// TestKeptAfterPrivate (§A.4 "Bounded redirects"): a result kept for the
// anonymous URL space isn't served once the namespace turns private: the
// read check comes first, and grant readers are sent to their subject
// set's URL space.
func TestKeptAfterPrivate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pub"))).CreateNamespace(ctx, "pub",
		map[string]any{"read": "public", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}))
	root := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"pub"}, []string{"read", "create", "config"})))
	must(root.CreateDoc(ctx, "pub", "a", map[string]any{"title": "x"}))
	x := startSvc(t, s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"pub"}, []string{"read"}))),
		svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pub"}, untyped: true, now: s.Now})
	at := x.caughtUp("pub")
	loc := "/pub/at/" + at + "?limit=5"
	if r := x.raw(loc, ""); r.status != 200 {
		t.Fatalf("public: %d %v", r.status, r.body)
	}
	must(root.PatchConfig(ctx, "pub", must(root.NSHead(ctx, "pub")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	x.caughtUp("pub")
	x.ix.ExpireGrantChecks()
	if r := x.raw(loc, ""); r.status != 401 {
		t.Errorf("anonymous after it turned private: %d %v", r.status, r.body)
	}
	bob := issuer.Grant(t, s.Now(), "user:bob", []string{"pub"}, []string{"read"})
	if r := x.raw(loc, bob); r.status != 302 || !strings.HasPrefix(r.header.Get("Location"), "/pub/g/") {
		t.Errorf("grant reader after it turned private: %d %s", r.status, r.header.Get("Location"))
	}
}
