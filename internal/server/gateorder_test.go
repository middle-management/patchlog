package server

// §6.2's gate order holds on every namespace-level write: an unauthenticated
// caller answers 401, a valid grant without the verb 403, a purged namespace
// 410, a missing precondition 428.

import (
	"strings"
	"testing"
)

// §6.2, §7.2: an unauthenticated caller answers 401 for every write path,
// whatever preconditions it omitted and whatever purged state the namespace
// is in. A valid grant without the verb answers 403 before a purged
// namespace's 410, which itself comes before the precondition's 428 (the
// order v0.32 pinned for blob uploads).
func TestReviewGateOrderNS(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	h := e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	cfg := e.configID("sec", f.adminG)
	// With authorisation, a missing precondition is 428 (§6.2 step 2), as
	// long as the namespace is live.
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/sec", body: ops(op("add", "/x-note", "n")), bearer: f.adminG}), 428, "precondition_required")
	expectCode(t, e.do(req{method: "POST", path: "/ns/sec/branches", body: map[string]any{"name": "r"}, bearer: f.adminG}), 428, "precondition_required")

	// 401, not 428 or 410, without credentials:
	unauth := []req{
		{method: "PATCH", path: "/r/sec/a", ifMatch: h, body: ops(op("add", "/x", 1.0))},
		{method: "DELETE", path: "/r/sec/a", ifMatch: h},
		{method: "POST", path: "/r/sec/a/purge", ifMatch: h},
		{method: "POST", path: "/r/sec/a/prune", body: map[string]any{"horizon": h}},
		{method: "POST", path: "/ns/sec/batch", body: map[string]any{"items": []any{}}},
		{method: "PATCH", path: "/ns/sec", ifMatch: cfg, body: ops(op("add", "/x-note", "n"))},
		{method: "PATCH", path: "/ns/sec", body: ops(op("add", "/x-note", "n"))},      // no precondition: no 428
		{method: "POST", path: "/ns/sec/branches", body: map[string]any{"name": "r"}}, // no If-None-Match: no 428
		{method: "POST", path: "/ns/sec/purge", ifMatch: e.nsHead("sec", f.adminG)},
		{method: "POST", path: "/ns/sec/branches", body: map[string]any{
			"remote": map[string]any{"origin": "https://b.example", "ns": "rel"}, "at": e.nsHead("sec", f.adminG)}},
	}
	for _, q := range unauth {
		expectCode(t, e.do(q), 401, "unauthenticated")
	}

	// A valid grant without the verb: 403, before a purged namespace's 410.
	expect(t, e.patchNS("sec", ops(op("add", "/frozen", true)), f.adminG), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/sec/purge", ifMatch: e.nsHead("sec", f.adminG), bearer: f.adminG}), 204)
	reader := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read"})
	batch := map[string]any{"items": []any{
		map[string]any{"resource": "z", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"z": true})}}}}
	purged := []req{
		{method: "PATCH", path: "/r/sec/a", ifMatch: h, body: ops(op("add", "/x", 1.0))},
		{method: "POST", path: "/r/sec/a/purge", ifMatch: h},
		{method: "POST", path: "/r/sec/a/prune", body: map[string]any{"horizon": h}},
		{method: "PATCH", path: "/ns/sec", ifMatch: cfg, body: ops(op("add", "/x-note", "n"))},
		{method: "POST", path: "/ns/sec/batch", body: batch},
		{method: "POST", path: "/ns/sec/branches", body: map[string]any{"name": "r"}},
	}
	for _, q := range purged {
		q.bearer = reader
		r := e.do(q)
		expect(t, r, 403)
		if q.path == "/ns/sec/batch" {
			// A batch reports its failing items under code "batch" (§7.5).
			items, _ := r.Obj()["items"].([]any)
			if len(items) != 1 || items[0].(map[string]any)["code"] != "forbidden" {
				t.Fatalf("batch report %s", r.Body)
			}
		} else if r.Str("code") != "forbidden" {
			t.Fatalf("%s %s: %s", q.method, q.path, r.Body)
		}
	}
	// An authorising grant reaches the 410.
	for _, q := range purged {
		if strings.HasSuffix(q.path, "/branches") {
			q.body = map[string]any{"name": "r", "patches": []any{}} // no If-None-Match
		}
		q.bearer = f.adminG
		expectCode(t, e.do(q), 410, "gone")
	}
}
