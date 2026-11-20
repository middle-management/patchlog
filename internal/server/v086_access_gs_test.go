package server

import (
	"testing"
	"time"
)

// CONFORMANCE Access 145 at the origin, over HTTP (SERVICES §7.9 view,
// v0.86): li holds a filtered view cookie for matches; matches changes the
// groups scope of the key her grant came from, then changes it back in a
// later config entry. On the cookie, at the later at, /heads, the log
// range, long-poll and events are 403 until she exchanges again; before
// v0.86 they were served again once the change was undone.
func TestV086FilteredCookieStaysEnded(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	g := w.li()
	c, vid := w.cookie(g)
	base := "/ns/matches/view/" + vid
	// paths are the reads at the current at, which li's grant names.
	paths := func() []string {
		_, at := w.filtered(w.li())
		head := w.nsHead("matches", w.admin)
		return []string{
			base + "/heads",
			base + "/at/" + at + "/heads",
			base + "/at/" + at + "/log",
			base + "/log?live=long-poll&since=" + head,
			base + "/events?since=" + head,
		}
	}
	refused := func(what string, ck map[string]string) {
		t.Helper()
		for _, p := range paths() {
			// A stream or a long-poll that is served never answers
			// here: it is given five seconds to refuse.
			done := make(chan *resp, 1)
			go func() { done <- w.do(req{method: "GET", path: p, hdr: ck}) }()
			select {
			case r := <-done:
				if r.Code != 403 {
					t.Errorf("%s: GET %s: %d %s, want 403", what, p, r.Code, r.Body)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: GET %s is being served, want 403", what, p)
			}
		}
	}
	old := cookieHdr(c)
	_, at := w.filtered(w.li())
	expect(t, w.do(req{method: "GET", path: base + "/at/" + at + "/heads", hdr: old}), 200)

	expect(t, w.patchNS("matches", ops(op("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}})), w.admin), 201)
	refused("after the key's groups scope changed", old)
	expect(t, w.patchNS("matches", ops(op("remove", "/keys/1/groups")), w.admin), 201)
	refused("after the change was undone", old)

	// She exchanges again, the same grant in the same second: the new
	// cookie expires a second before the ended one, to be told apart
	// from it (§C.5.2), and reads at the later at; the old one stays
	// ended.
	c2, gs2 := w.cookie(g)
	if gs2 != vid {
		t.Fatalf("vid after the undo %s, was %s", gs2, vid)
	}
	if !c2.Expires.Equal(c.Expires.Add(-time.Second)) {
		t.Fatalf("the new cookie expires %v, the ended one %v: want a second earlier", c2.Expires, c.Expires)
	}
	fresh := cookieHdr(c2)
	_, at = w.filtered(w.li())
	expect(t, w.do(req{method: "GET", path: base + "/heads", hdr: fresh}), 302)
	expect(t, w.do(req{method: "GET", path: base + "/at/" + at + "/heads", hdr: fresh}), 200)
	expect(t, w.do(req{method: "GET", path: base + "/at/" + at + "/log", hdr: fresh}), 200)
	refused("the old cookie after she exchanged again", old)
}
