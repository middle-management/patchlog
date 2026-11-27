package server

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

// v0.88 §7.9 Partial reader, §9 ("a /ns/{ns} cookie's reads at view URLs"),
// Filtered reads scenario 8: an unrestricted reader's /ns/{ns} cookie at a
// view's URLs reads every revision, its answers private, no-store, and
// no-store at the edge too, never shared with the view's readers.
func TestV088FullReaderCookieAtViewURLs(t *testing.T) {
	w := newV75s(t, v75sOpts{})
	w.seed(nil, nil, []string{"derby"})
	hid := w.v87Doc("matches", "hid", map[string]any{"team": "b"})
	vid, at := w.filtered(w.li())
	r := w.do(req{method: "POST", path: "/edge-grants", bearer: w.grant(w.k, "user:root", []string{"matches"}, []string{"read"})})
	expect(t, r, 200)
	c, ok := edgeCookies(t, r)["/ns/matches"]
	if !ok {
		t.Fatalf("no /ns/matches cookie: %v", r.H.Values("Set-Cookie"))
	}
	base := "/ns/matches/view/" + vid
	for _, p := range []string{base + "/at/" + at + "/heads", base + "/at/" + at + "/log", base + "/r/hid/rev/" + hid} {
		r := w.do(req{method: "GET", path: p, hdr: cookieHdr(c)})
		expect(t, r, 200)
		expectPrivateNoStore(t, r)
	}
}

// v0.88 §7.9 URLs ("Ranges are immutable but for purges and archive
// restores since", tagged as their unfiltered forms, ns:{ns}): once a
// view has been recorded in matches, a resource purge there purges
// ns:matches, which its filtered ranges carry, besides the purge's own
// tags; a namespace no view was recorded for keeps ns:{ns}. (Restores are
// in core, TestV088RestoreTagsFilteredRanges.)
func TestV088PurgeTagsFilteredRanges(t *testing.T) {
	rec := &recPurger{}
	w := newV75s(t, v75sOpts{env: []envOpt{func(o *core.Options) { o.Purger = rec }}})
	adminP := w.grant(w.k, "user:root", []string{"matches"}, []string{"read", "create", "append", "purge"})
	x := w.v87Doc("matches", "x", map[string]any{"team": "a"})
	rec.take()
	expect(t, w.purge("matches", "x", x, adminP), 204)
	if calls := rec.take(); purged(calls, "ns:matches") || !purged(calls, "r:matches/x") {
		t.Fatalf("a purge with no view recorded: %v, want r:matches/x without ns:matches", calls)
	}
	w.seed(nil, nil, []string{"derby"})
	w.cookie(w.li())
	y := w.v87Doc("matches", "y", map[string]any{"team": "a"})
	rec.take()
	expect(t, w.purge("matches", "y", y, adminP), 204)
	if calls := rec.take(); !purged(calls, "ns:matches") {
		t.Fatalf("a purge once a view is recorded: %v, want ns:matches among them", calls)
	}
}

// v0.88 Filtered reads scenario 17, §8.5: once matches is purged, a
// partial reader whose only rule tests /doc gets the namespace's 410 at a
// resource's URL, her /doc rule set aside. Until v0.88 it was 404.
func TestV088PurgedNamespaceGoneToDocReader(t *testing.T) {
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	li := w.li()
	opg := mint(t, w.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"matches"}, "can": []any{"purge-ns"},
		"exp": w.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	expect(t, w.patchNS("matches", ops(op("add", "/frozen", true)), w.admin), 201)
	expect(t, w.do(req{method: "POST", path: "/ns/matches/purge?force=1", ifMatch: w.nsHead("matches", w.admin), bearer: opg}), 204)
	for _, p := range []string{"/r/matches/derby", "/r/matches/derby/log"} {
		expectCode(t, w.get(p, li), 410, "purged")
	}
}

// v0.88 §8.3 Responses, §6.4.1 read ("except in the read check for a
// purged resource's 410, which sets such rules aside, alls flattened"),
// Filtered reads scenario 64: a purged resource is 410 to a reader whose
// rules fail only for want of doc, at its head, revision, log and raw
// URLs; a reader whose other rules refuse the name keeps the 404 of any
// read it may not make. Until v0.88 a reader whose rules test /doc got
// 404 there.
func TestV088PurgedResourceGoneToDocReader(t *testing.T) {
	w := newV75s(t, v75sOpts{})
	li := w.grant(w.k, "user:li", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{v87TeamA}})
	// /doc and /resource in one all: flattened, its /resource test still
	// refuses another name.
	only := map[string]any{"all": []any{
		map[string]any{"op": "test", "path": "/resource", "value": "other"},
		v87TeamA,
	}}
	nope := w.grant(w.k, "user:nope", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{only}})
	adminP := w.grant(w.k, "user:root", []string{"matches"}, []string{"read", "create", "append", "purge"})
	bid := w.upload("matches", "secret", "text/plain", []byte("s"), w.admin)
	h := w.v87Doc("matches", "secret", map[string]any{"team": "a", "file": map[string]any{"": bid, "type": "text/plain", "size": 1.0}})
	expect(t, w.get("/r/matches/secret", li), 302)
	expect(t, w.purge("matches", "secret", h, adminP), 204)
	for _, p := range []string{"/r/matches/secret", "/r/matches/secret/rev/" + h, "/r/matches/secret/log", "/r/matches/secret/raw",
		"/r/matches/secret/blob/" + bid, "/r/matches/secret/blob/" + bid + "/e/1", "/r/matches/secret/log?live=long-poll", "/r/matches/secret/events"} {
		r := w.v87Get(p, li)
		if r.Code != 410 {
			t.Errorf("GET %s by a /doc reader after the purge: %d %s, want 410 (§8.3, rules on /doc set aside)", p, r.Code, r.Body)
		}
		if r := w.v87Get(p, nope); r.Code != 404 {
			t.Errorf("GET %s by a reader whose /resource rule refuses the name: %d %s, want 404", p, r.Code, r.Body)
		}
	}
}
