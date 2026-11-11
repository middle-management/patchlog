package server

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// V82-02 (v0.82), ACC-14 over HTTP: a gs cookie ends when its key's entry
// changes in any member, until the reader exchanges again; long-poll
// judges it at the current checkpoint (SERVICES §B.11.9 gs).

// §B.11.9 gs: "A gs cookie is 403 ... [where] the key its key: string
// names, or a key or role they came from, is gone or changes in any
// member, until the reader exchanges again. Long-poll judges this at the
// current checkpoint." li's cookie reads; catalog-01's entry gains a
// maxLag, which no rule, pub or subject reads, while her long-poll under
// the cookie waits: the wake is 403, never a page with the config entry,
// and so is every filtered URL under the cookie, until she exchanges
// again. Before v0.82 the cookie was served on.
func TestV082AccessGSCookieEndsOnKeyChange(t *testing.T) {
	t.Parallel()
	interval := 2 * time.Second
	w := newV75s(t, v75sOpts{env: []envOpt{withLongPoll(interval)}})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	li := w.li()
	c, gs := w.cookie(li)
	ck := cookieHdr(c)
	base := "/ns/matches/g/" + gs
	r := w.do(req{method: "GET", path: base + "/heads", hdr: ck})
	expect(t, r, 302)
	at := r.H.Get("Location")
	expect(t, w.do(req{method: "GET", path: at, hdr: ck}), 200)

	since := w.nsHead("matches", w.admin)
	cur := waitCursor(interval, 1500*time.Millisecond)
	done := make(chan *resp, 1)
	go func() {
		done <- w.do(req{method: "GET", path: base + "/log?live=long-poll&since=" + since + "&cursor=" + strconv.FormatInt(cur, 10), hdr: ck})
	}()
	time.Sleep(200 * time.Millisecond)
	expect(t, w.patchNS("matches", ops(op("add", "/keys/1/maxLag", "PT50S")), w.admin), 201)
	res := <-done
	if res.Code != 403 || strings.Contains(res.String(), "maxLag") {
		t.Fatalf("the waiting long-poll under the cookie: %d %s, want 403", res.Code, res.Body)
	}
	for _, path := range []string{base + "/heads", base + "/log?since=" + since, base + "/log?live=long-poll&since=" + since, base + "/events?since=" + since} {
		if r := w.do(req{method: "GET", path: path, hdr: ck}); r.Code != 403 {
			t.Errorf("%s under the old cookie: %d %s, want 403", path, r.Code, r.Body)
		}
	}
	// Her grant still verifies: she exchanges again, for the same gs.
	c2, gs2 := w.cookie(w.li())
	if gs2 != gs {
		t.Fatalf("gs after the change %s, was %s", gs2, gs)
	}
	r = w.do(req{method: "GET", path: base + "/heads", hdr: cookieHdr(c2)})
	expect(t, r, 302)
	r = w.do(req{method: "GET", path: r.H.Get("Location"), hdr: cookieHdr(c2)})
	expect(t, r, 200)
	if names := headNames(t, r); len(names) != 1 || names[0] != "derby" {
		t.Fatalf("after exchanging again: %v", names)
	}
}
