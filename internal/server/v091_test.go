package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Spec v0.91 §8.5 Answers afterwards (CONFORMANCE DEL-9, scenario 106):
// every request to /r/{ns}/… or /ns/{ns} and below of a purged namespace
// is 410 purged, with head the purge-ns entry's id, whatever the grant:
// without credentials, with an expired grant, one an unknown key signed,
// or one whose ns doesn't name it. A read's 410 is cached as long, with
// the public class whatever the namespace's read was, where its URL
// isn't no-store; only creating a namespace or a branch under its name is
// 412 instead.
func TestV091PurgedNamespaceEveryRoute(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	star := newKey("star")
	all := []string{"read", "append", "create", "delete", "restore", "config", "branch", "purge", "purge-ns", "prune"}
	e.mkNS("old", map[string]any{"keys": []any{star.entry("*")}})
	admin := e.grant(star, "user:admin", []string{"old"}, all)
	r := e.do(req{method: "PATCH", path: "/r/old/derby", ifNoneMatch: "*", body: ops(op("add", "", map[string]any{"n": 1})), bearer: admin, ct: jsonPatchType})
	expect(t, r, 201)
	rev := strings.Trim(r.H.Get("ETag"), `"`)
	at := e.nsHead("old", admin)
	head := e.purgeNSAs("old", admin)
	if head == "" {
		t.Fatal("no purge-ns id")
	}

	other := newKey("other")
	expired := e.grant(star, "user:admin", []string{"old"}, all, map[string]any{"exp": e.clock.Now().Add(-time.Minute).Format(time.RFC3339)})
	creds := map[string]string{
		"none":        "",
		"expired":     expired,
		"unknown key": e.grant(other, "user:x", []string{"old"}, []string{"read"}),
		"other ns":    e.grant(star, "user:x", []string{"matches"}, []string{"read"}),
		"admin":       admin,
	}
	bid := rev // any id in text form
	patch := ops(op("add", "/n", 2))
	routes := []req{
		{method: "GET", path: "/r/old/derby"},
		{method: "PATCH", path: "/r/old/derby", ifMatch: rev, body: patch, ct: jsonPatchType},
		{method: "DELETE", path: "/r/old/derby", ifMatch: rev},
		{method: "GET", path: "/r/old/derby/rev/" + rev},
		{method: "GET", path: "/r/old/derby/rev/" + rev + "/log"},
		{method: "GET", path: "/r/old/derby/raw"},
		{method: "GET", path: "/r/old/derby/rev/" + rev + "/raw"},
		{method: "GET", path: "/r/old/derby/log?since=" + rev + "&live=long-poll"},
		{method: "GET", path: "/r/old/derby/events"},
		{method: "POST", path: "/r/old/derby/purge", ifMatch: rev},
		{method: "POST", path: "/r/old/derby/prune", body: map[string]any{"horizon": rev}},
		{method: "PUT", path: "/r/old/derby/blob/" + bid, raw: "x", ct: "text/plain"},
		{method: "GET", path: "/r/old/derby/blob/" + bid},
		{method: "GET", path: "/r/old/derby/blob/" + bid + "/e/1"},
		{method: "GET", path: "/ns/old"},
		{method: "PATCH", path: "/ns/old", ifMatch: at, body: patch, ct: jsonPatchType},
		{method: "GET", path: "/ns/old/rev/" + head},
		{method: "GET", path: "/ns/old/rev/" + at + "/log"},
		{method: "GET", path: "/ns/old/rev/" + head + "/heads"},
		{method: "GET", path: "/ns/old/log?since=" + at + "&live=long-poll"},
		{method: "GET", path: "/ns/old/events"},
		{method: "GET", path: "/ns/old/view/" + head + "/at/" + at + "/heads"},
		{method: "GET", path: "/ns/old/view/" + head + "/at/" + at + "/log"},
		{method: "GET", path: "/ns/old/view/" + head + "/heads"},
		{method: "GET", path: "/ns/old/view/" + head + "/log"},
		{method: "GET", path: "/ns/old/view/" + head + "/events"},
		{method: "GET", path: "/ns/old/view/" + head + "/r/derby/rev/" + rev},
		{method: "GET", path: "/ns/old/view/" + head + "/r/derby/blob/" + bid},
		{method: "GET", path: "/ns/old/gestures/" + strings.Repeat("a", 26)},
		{method: "GET", path: "/ns/old/principal"},
		{method: "GET", path: "/ns/old/grants/" + head},
		{method: "GET", path: "/ns/old/branches"},
		{method: "POST", path: "/ns/old/branches", ifNoneMatch: "*", body: map[string]any{"name": "old-b"}},
		{method: "POST", path: "/ns/old/batch", body: map[string]any{"items": []any{map[string]any{"resource": "x", "ifNoneMatch": "*", "steps": []any{ops(op("add", "", map[string]any{}))}}}}},
		{method: "POST", path: "/ns/old/purge", ifMatch: head},
		{method: "POST", path: "/ns/old/keys", body: map[string]any{}},
	}
	for _, rq := range routes {
		for who, bearer := range creds {
			q := rq
			q.bearer = bearer
			if bearer == "" {
				q.author = "x"
			}
			got := e.do(q)
			if got.Code != 410 {
				t.Errorf("%s %s (%s): %d %s, want 410", q.method, q.path, who, got.Code, got.Body)
				continue
			}
			var body map[string]any
			_ = json.Unmarshal(got.Body, &body)
			if body["code"] != "purged" || body["head"] != head {
				t.Errorf("%s %s (%s): %s, want purged with head %s", q.method, q.path, who, got.Body, head)
			}
			if q.method == "GET" {
				cc := got.H.Get("Cache-Control")
				if cc != "no-store" && cc != ccLong {
					t.Errorf("%s %s (%s): Cache-Control %q, want %q or no-store", q.method, q.path, who, cc, ccLong)
				}
			}
		}
	}
	// The cacheable reads are cached as long, publicly: the namespace was
	// private.
	for _, p := range []string{"/ns/old/rev/" + at + "/log", "/r/old/derby/rev/" + rev, "/ns/old/rev/" + head + "/heads"} {
		if cc := e.get(p).H.Get("Cache-Control"); cc != ccLong {
			t.Errorf("GET %s: Cache-Control %q, want %q", p, cc, ccLong)
		}
	}
	// Creating it again is 412: its name stays reserved (§7.6).
	expect(t, e.do(req{method: "PATCH", path: "/ns/old", ifNoneMatch: "*", body: ops(op("add", "", map[string]any{})), bearer: e.lister(), ct: jsonPatchType}), 412)
}

// CONFORMANCE Filtered reads scenario 98 (§7, §7.9 Where, §C.5.2, v0.91):
// in a public, unsealed namespace a partial reader learns its view from the
// exchange's prefixes. Its grant at another view is 403; a grant whose ns
// doesn't name the namespace is 403 at its prefix, never 401, and is
// ignored at the unfiltered /heads, answered 200 unfiltered.
func TestV091PublicViewFromExchange(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{matches: func(doc map[string]any) { doc["read"] = "public" }})
	w.seed([]string{"derby"}, []string{"secret"}, []string{"derby", "secret"})
	li := w.li()
	r := w.do(req{method: "POST", path: "/edge-grants", bearer: li})
	expect(t, r, 200)
	var view string
	for _, p := range r.Obj()["prefixes"].([]any) {
		if s, _ := p.(string); strings.HasPrefix(s, "/ns/matches/view/") {
			view = strings.TrimPrefix(s, "/ns/matches/view/")
		}
	}
	if view == "" {
		t.Fatalf("no view prefix among %s", r.Body)
	}
	at := w.nsHead("matches", w.admin)
	expect(t, w.get("/ns/matches/view/"+view+"/at/"+at+"/heads", li), 200)
	expect(t, w.get("/ns/matches/view/1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/at/"+at+"/heads", li), 403)
	other := w.grant(w.k, "user:x", []string{"cat-season"}, []string{"read"})
	expectCode(t, w.get("/ns/matches/view/"+view+"/at/"+at+"/heads", other), 403, "forbidden")
	u := w.get("/ns/matches/rev/"+at+"/heads", other)
	expect(t, u, 200)
	if !strings.Contains(string(u.Body), `"secret"`) {
		t.Fatalf("the unfiltered /heads to a grant it ignores: %s", u.Body)
	}
}
