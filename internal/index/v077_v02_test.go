package index_test

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// V77-02 (v0.77): the index's markers, scope cookies, coverage, exchange
// 410, /_refs, purges before serving, upstream errors and judged-once
// epochs (§A.1, §A.4, §B.11.9, §C.4, §E.2.6).

// TestV077MembersBehindNamesNone (FSVC-12; §A.4 Private namespaces: a
// partial reader is answered "503 (behind, §B.5) until it has reached
// each"; /principal hides catalog.trust, §7.4): before cat-season's
// follower holds its first checkpoint, li's 503 at /matches and at /_refs
// doesn't name cat-season. Before v0.77 its body did.
func TestV077MembersBehindNamesNone(t *testing.T) {
	t.Parallel()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	x, _ := members76Start(t, w, filepath.Join(t.TempDir(), "i.db"), func(ctx context.Context, m string) {
		if m == "cat-season" {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	})
	x.ix.SetMinWait(50 * time.Millisecond)
	w.x = x
	x.caughtUp("matches")
	li := w.reader("user:li", []any{"fans"})
	for _, path := range []string{"/matches", "/_refs?to=%2Fr%2Ftarget%2Fx"} {
		r := x.raw(path, li)
		if r.status != 503 || r.body["code"] != "behind" || strings.Contains(r.body["message"].(string), "cat-season") {
			t.Errorf("%s before cat-season's first checkpoint: %d %v", path, r.status, r.body)
		}
	}
}

// TestV077HeadPointerDropsOpaqueAfter (FSVC-8, index part; §A.4: "A
// redirect from a head pointer or to another at ... keeps an after naming
// a resource, applied to the new result, and drops an opaque one, starting
// again"): GET /matches?q=…&after=<an opaque next> is a 302 whose Location
// has no after; with a resource-naming after, it keeps it. Before v0.77
// the head pointer passed an opaque after on.
func TestV077HeadPointerDropsOpaqueAfter(t *testing.T) {
	t.Parallel()
	w := setup(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}})
	w.doc(t, "a1", w.match, map[string]any{"title": "word one"})
	w.doc(t, "a2", w.match, map[string]any{"title": "word two"})
	cur := s.caughtUp("matches")
	b := s.search("/matches?limit=1&q=word", "")
	next, _ := b["next"].(string)
	if next == "" {
		t.Fatalf("no next: %v", b)
	}
	r := s.raw("/matches?after="+url.QueryEscape(next)+"&limit=1&q=word", "")
	if loc := r.header.Get("Location"); r.status != 302 || loc != "/matches/at/"+cur+"?limit=1&q=word" {
		t.Errorf("head pointer with an opaque after: %d %s", r.status, loc)
	}
	r = s.raw("/matches?after=1&limit=1&sort=%2Ftitle", "")
	if loc := r.header.Get("Location"); r.status != 302 || loc != "/matches/at/"+cur+"?limit=1&sort=%2Ftitle" {
		t.Errorf("head pointer with sort's opaque after: %d %s", r.status, loc)
	}
	r = s.raw("/matches?after=a1&limit=1", "")
	if loc := r.header.Get("Location"); r.status != 302 || loc != "/matches/at/"+cur+"?after=a1&limit=1" {
		t.Errorf("head pointer with an after naming a resource: %d %s", r.status, loc)
	}
}
