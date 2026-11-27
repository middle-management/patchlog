package server

import (
	"encoding/json"
	"os"
	"regexp"
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
	// Each route the server registers under /r/{ns} or /ns/{ns}, by
	// pattern, the URLs that are no-store whatever they answer marked.
	type route struct {
		pattern string
		noStore bool
		q       req
	}
	routes := []route{
		{"GET /r/{ns}/{name}", false, req{method: "GET", path: "/r/old/derby"}},
		{"PATCH /r/{ns}/{name}", true, req{method: "PATCH", path: "/r/old/derby", ifMatch: rev, body: patch, ct: jsonPatchType}},
		{"DELETE /r/{ns}/{name}", true, req{method: "DELETE", path: "/r/old/derby", ifMatch: rev}},
		{"GET /r/{ns}/{name}/rev/{id}", false, req{method: "GET", path: "/r/old/derby/rev/" + rev}},
		{"GET /r/{ns}/{name}/rev/{id}/log", false, req{method: "GET", path: "/r/old/derby/rev/" + rev + "/log"}},
		{"GET /r/{ns}/{name}/raw", false, req{method: "GET", path: "/r/old/derby/raw"}},
		{"GET /r/{ns}/{name}/rev/{id}/raw", false, req{method: "GET", path: "/r/old/derby/rev/" + rev + "/raw"}},
		{"GET /r/{ns}/{name}/log", false, req{method: "GET", path: "/r/old/derby/log?since=" + rev + "&live=long-poll"}},
		{"GET /r/{ns}/{name}/events", true, req{method: "GET", path: "/r/old/derby/events"}},
		{"POST /r/{ns}/{name}/purge", true, req{method: "POST", path: "/r/old/derby/purge", ifMatch: rev}},
		{"POST /r/{ns}/{name}/prune", true, req{method: "POST", path: "/r/old/derby/prune", body: map[string]any{"horizon": rev}}},
		{"PUT /r/{ns}/{name}/blob/{bid}", true, req{method: "PUT", path: "/r/old/derby/blob/" + bid, raw: "x", ct: "text/plain"}},
		{"GET /r/{ns}/{name}/blob/{bid}", false, req{method: "GET", path: "/r/old/derby/blob/" + bid}},
		{"GET /r/{ns}/{name}/blob/{bid}/e/{e}", false, req{method: "GET", path: "/r/old/derby/blob/" + bid + "/e/1"}},
		{"GET /ns/{ns}", false, req{method: "GET", path: "/ns/old"}},
		{"PATCH /ns/{ns}", true, req{method: "PATCH", path: "/ns/old", ifMatch: at, body: patch, ct: jsonPatchType}},
		{"GET /ns/{ns}/rev/{id}", false, req{method: "GET", path: "/ns/old/rev/" + head}},
		{"GET /ns/{ns}/rev/{id}/log", false, req{method: "GET", path: "/ns/old/rev/" + at + "/log"}},
		{"GET /ns/{ns}/rev/{id}/heads", false, req{method: "GET", path: "/ns/old/rev/" + head + "/heads"}},
		{"GET /ns/{ns}/log", false, req{method: "GET", path: "/ns/old/log?since=" + at + "&live=long-poll"}},
		{"GET /ns/{ns}/events", true, req{method: "GET", path: "/ns/old/events"}},
		{"GET /ns/{ns}/view/{view}/at/{at}/heads", false, req{method: "GET", path: "/ns/old/view/" + head + "/at/" + at + "/heads"}},
		{"GET /ns/{ns}/view/{view}/at/{at}/log", false, req{method: "GET", path: "/ns/old/view/" + head + "/at/" + at + "/log"}},
		{"GET /ns/{ns}/view/{view}/heads", false, req{method: "GET", path: "/ns/old/view/" + head + "/heads"}},
		{"GET /ns/{ns}/view/{view}/log", false, req{method: "GET", path: "/ns/old/view/" + head + "/log"}},
		{"GET /ns/{ns}/view/{view}/events", true, req{method: "GET", path: "/ns/old/view/" + head + "/events"}},
		{"GET /ns/{ns}/view/{view}/r/{name}/rev/{id}", false, req{method: "GET", path: "/ns/old/view/" + head + "/r/derby/rev/" + rev}},
		{"GET /ns/{ns}/view/{view}/r/{name}/blob/{bid}", false, req{method: "GET", path: "/ns/old/view/" + head + "/r/derby/blob/" + bid}},
		{"GET /ns/{ns}/gestures/{gesture}", true, req{method: "GET", path: "/ns/old/gestures/" + strings.Repeat("a", 26)}},
		{"GET /ns/{ns}/principal", true, req{method: "GET", path: "/ns/old/principal"}},
		{"GET /ns/{ns}/grants/{gid}", false, req{method: "GET", path: "/ns/old/grants/" + head}},
		{"GET /ns/{ns}/branches", false, req{method: "GET", path: "/ns/old/branches"}},
		{"POST /ns/{ns}/branches", true, req{method: "POST", path: "/ns/old/branches", ifNoneMatch: "*", body: map[string]any{"name": "old-b"}}},
		{"POST /ns/{ns}/batch", true, req{method: "POST", path: "/ns/old/batch", body: map[string]any{"items": []any{map[string]any{"resource": "x", "ifNoneMatch": "*", "steps": []any{ops(op("add", "", map[string]any{}))}}}}}},
		{"POST /ns/{ns}/purge", true, req{method: "POST", path: "/ns/old/purge", ifMatch: head}},
		{"POST /ns/{ns}/keys", true, req{method: "POST", path: "/ns/old/keys", body: map[string]any{}}},
		{"GET /ns/{ns}/view/{view}/r/{name}/rev/{id}/raw", false, req{method: "GET", path: "/ns/old/view/" + head + "/r/derby/rev/" + rev + "/raw"}},
		{"GET /ns/{ns}/view/{view}/r/{name}/blob/{bid}/e/{e}", false, req{method: "GET", path: "/ns/old/view/" + head + "/r/derby/blob/" + bid + "/e/1"}},
	}
	listed := map[string]bool{}
	for _, rt := range routes {
		listed[rt.pattern] = true
	}
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`HandleFunc\("([A-Z]+ /(?:r|ns)/\{ns\}[^"]*)"`).FindAllStringSubmatch(string(src), -1) {
		if !listed[m[1]] {
			t.Errorf("route %s isn't swept: add it", m[1])
		}
	}
	for _, rt := range routes {
		for who, bearer := range creds {
			q := rt.q
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
			cc := got.H.Get("Cache-Control")
			switch {
			case rt.noStore || q.method != "GET":
				if cc != "no-store" {
					t.Errorf("%s %s (%s): Cache-Control %q, want no-store", q.method, q.path, who, cc)
				}
			case cc != ccLong || !strings.Contains(got.H.Get("Cache-Tag"), "ns:old"):
				t.Errorf("%s %s (%s): Cache-Control %q, Cache-Tag %q, want %q and ns:old", q.method, q.path, who, cc, got.H.Get("Cache-Tag"), ccLong)
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
