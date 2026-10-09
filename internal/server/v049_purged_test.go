package server

import (
	"context"
	"testing"
	"time"
)

// expectPurged expects the 410 "purged" of a purged namespace, whose head
// names its purge-ns entry (§8.5, §12).
func expectPurged(t *testing.T, r *resp, head string) {
	t.Helper()
	expectCode(t, r, 410, "purged")
	if got := r.Str("head"); got != head {
		t.Fatalf("head %q, want %q: %s", got, head, r.Body)
	}
}

// nsPurge freezes ns and purges it, returning the purge-ns entry's ns_id.
func (e *tenv) nsPurge(ns string) string {
	e.t.Helper()
	expect(e.t, e.patchNS(ns, ops(op("add", "/frozen", true)), ""), 201)
	r := e.do(req{method: "POST", path: "/ns/" + ns + "/purge", ifMatch: e.nsHead(ns), author: "admin"})
	expect(e.t, r, 204)
	head := e.nsHead(ns)
	if lastOf(e.nsKinds(ns)) != "purge-ns" {
		e.t.Fatalf("log %v", e.nsKinds(ns))
	}
	return head
}

// v0.49 §8.5: every write to a purged namespace is 410 "purged" after
// authorisation and the rate limits and before any other check, the
// idempotent-retry lookup included: resource writes, batches (config-only
// too), blob uploads and copies, purges, prunes, config writes, branching
// and remote registration. Every such 410, and those of its URLs
// (/ns/{ns}/keys among them), carries head, the purge-ns entry, which
// stays the log's last; /ns/{ns} and its log stay readable.
func TestV049PurgedWrites(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("p", map[string]any{"read": "public"})
	e.mkNS("src", map[string]any{"read": "public"})
	a0 := e.create("p", "a", map[string]any{"n": 0.0})
	next := ops(op("replace", "/n", 1.0))
	a1 := e.appendRev("p", "a", a0, next)
	bid := e.upload("src", "s", "text/plain", []byte("x"))
	cfg := e.configID("p")
	at := e.nsHead("p")
	head := e.nsPurge("p")
	cfg2 := e.configID("p")

	batch := func(body map[string]any) req {
		return req{method: "POST", path: "/ns/p/batch", body: body, author: "alice"}
	}
	item := map[string]any{"resource": "z", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}
	change := map[string]any{"ifMatch": cfg2, "patches": ops(op("add", "/x-note", "n"))}
	for name, q := range map[string]req{
		// Retries of writes made before the purge: the lookup doesn't apply.
		"retried append": {method: "PATCH", path: "/r/p/a", ifMatch: a0, body: next, author: "alice"},
		"retried freeze": {method: "PATCH", path: "/ns/p", ifMatch: cfg, body: ops(op("add", "/frozen", true)), author: "admin"},
		"append":         {method: "PATCH", path: "/r/p/a", ifMatch: a1, body: next, author: "alice"},
		"create":         {method: "PATCH", path: "/r/p/n", ifNoneMatch: "*", body: addRoot(map[string]any{}), author: "alice"},
		"delete":         {method: "DELETE", path: "/r/p/a", ifMatch: a1, author: "alice"},
		"stale append":   {method: "PATCH", path: "/r/p/a", ifMatch: a0, body: ops(op("add", "/x", 1.0)), author: "alice"},
		"batch":          batch(map[string]any{"items": []any{item}}),
		"dry run":        {method: "POST", path: "/ns/p/batch?dry-run=1", body: map[string]any{"items": []any{item}}, author: "alice"},
		"config batch":   batch(map[string]any{"config": change}),
		"stale config batch": batch(map[string]any{"config": map[string]any{
			"ifMatch": cfg, "patches": ops(op("add", "/x-note", "n"))}}),
		"config and items": batch(map[string]any{"config": change, "items": []any{item}}),
		"upload":           {method: "PUT", path: blobPath("p", "a", bid), raw: "x", hasRaw: true, ct: "text/plain", author: "alice"},
		"copy":             {method: "PUT", path: blobPath("p", "a", bid), hdr: map[string]string{"Blob-From": blobPath("src", "s", bid)}, author: "alice"},
		"purge":            {method: "POST", path: "/r/p/a/purge", ifMatch: a1, author: "admin"},
		"stale purge":      {method: "POST", path: "/r/p/a/purge", ifMatch: a0, author: "admin"},
		"forced purge":     {method: "POST", path: "/r/p/a/purge?force=1", ifMatch: a1, author: "admin"},
		"purge-ns":         {method: "POST", path: "/ns/p/purge", ifMatch: head, author: "admin"},
		"forced purge-ns":  {method: "POST", path: "/ns/p/purge?force=1", ifMatch: head, author: "admin"},
		"prune":            {method: "POST", path: "/r/p/a/prune", body: map[string]any{"horizon": a1}, author: "admin"},
		"config":           {method: "PATCH", path: "/ns/p", ifMatch: cfg2, body: ops(op("add", "/frozen", false)), author: "admin"},
		"stale config":     {method: "PATCH", path: "/ns/p", ifMatch: cfg, body: ops(op("add", "/x-note", "n")), author: "admin"},
		"no precondition":  {method: "PATCH", path: "/ns/p", body: ops(op("add", "/x-note", "n")), author: "admin"},
		"branch":           {method: "POST", path: "/ns/p/branches", ifNoneMatch: "*", body: map[string]any{"name": "pb", "at": at}, author: "alice"},
		"registration": {method: "POST", path: "/ns/p/branches", ifNoneMatch: "*", author: "alice",
			body: map[string]any{"remote": map[string]any{"origin": originB, "ns": "rel"}, "at": at}},
	} {
		r := e.do(q)
		if r.Code != 410 || r.Str("code") != "purged" || r.Str("head") != head {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	// Reads after the read check, /ns/{ns}/keys too.
	for _, p := range []string{"/r/p/a", "/r/p/a/rev/" + a0, "/r/p/a/blob/" + bid, "/ns/p/rev/" + at + "/heads", "/ns/p/gestures/" + gA} {
		expectPurged(t, e.get(p), head)
	}
	expectPurged(t, e.do(req{method: "POST", path: "/ns/p/keys"}), head)

	// Nothing followed the purge-ns entry; /ns/{ns} and its log still read.
	if e.nsHead("p") != head || e.configID("p") != cfg2 || lastOf(e.nsKinds("p")) != "purge-ns" {
		t.Fatalf("log after the refused writes %v", e.nsKinds("p"))
	}
}

// v0.49 §8.5, §6.2: the 410 comes after authorisation and the rate limits,
// those of a batch's items and config change included, and /ns/{ns}/keys
// answers it after its read check.
func TestV049PurgedGateOrder(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, map[string]any{"limits": map[string]any{
		"ratePerPrincipal": map[string]any{"rate": 0.001, "burst": 1}}})
	e := f.tenv
	e.create("sec", "a", map[string]any{}, f.adminG)
	expect(t, e.patchNS("sec", ops(op("add", "/frozen", true)), f.adminG), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/sec/purge", ifMatch: e.nsHead("sec", f.adminG), bearer: f.adminG}), 204)
	head := e.nsHead("sec", f.adminG)
	change := func(who string, items ...any) *resp {
		body := map[string]any{"config": map[string]any{
			"ifMatch": e.configID("sec", f.adminG), "patches": ops(op("add", "/x-note", "n"))}}
		if len(items) > 0 {
			body["items"] = items
		}
		return e.batchReq("sec", body, who)
	}

	// A batch's items are authorised before the 410, with its config
	// change: a grant that may change the configuration but not create
	// gets the 403 of its item.
	configOnly := e.grant(f.issuer, "user:c", []string{"sec"}, []string{"read", "config"})
	r := change(configOnly, map[string]any{"resource": "z", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}})
	expect(t, r, 403)
	if items, _ := r.Obj()["items"].([]any); len(items) != 1 || items[0].(map[string]any)["code"] != "forbidden" {
		t.Fatalf("batch report %s", r.Body)
	}
	// The config change draws its token before the 410: the next is 429.
	expectPurged(t, change(f.issuerG), head)
	expectCode(t, change(f.issuerG), 429, "rate")

	// /ns/{ns}/keys: 401 without a grant, 404 without read or with rules
	// refusing it, then 410.
	keys := func(bearer string) *resp { return e.do(req{method: "POST", path: "/ns/sec/keys", bearer: bearer}) }
	expectCode(t, keys(""), 401, "unauthenticated")
	expectCode(t, keys(e.grant(f.issuer, "user:w", []string{"sec"}, []string{"append"})), 404, "not_found")
	expectCode(t, keys(e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read", "append"}, refusesReads)), 404, "not_found")
	expectPurged(t, keys(f.adminG), head)
	if e.nsHead("sec", f.adminG) != head {
		t.Fatal("an entry followed purge-ns")
	}
}

// refusesReads is a grant's rules passing appends only.
var refusesReads = map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/action", "value": "append"}}}

// v0.49 §8.5: in sealed and end-to-end namespaces too, /ns/{ns}/keys and
// the gestures listing, which a live one doesn't offer, answer 410 after
// the read check, a grant's rules included.
func TestV049PurgedEncrypted(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	expect(t, e.write("PATCH", "s", "a", "", withNonce(addRoot(map[string]any{}))), 201)
	expect(t, e.patchNS("s", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/s/purge", ifMatch: e.nsHead("s"), author: "admin"}), 204)
	head := e.nsHead("s")
	expectPurged(t, e.get("/ns/s/gestures/"+gA), head)
	expectPurged(t, e.do(req{method: "POST", path: "/ns/s/keys"}), head)

	f := newE2E(t)
	expect(t, f.patchNS("e", ops(op("add", "/frozen", true)), f.adminG), 201)
	expect(t, f.do(req{method: "POST", path: "/ns/e/purge", ifMatch: f.nsHead("e", f.adminG), bearer: f.adminG}), 204)
	head = f.nsHead("e", f.adminG)
	keys := func(bearer string) *resp { return f.do(req{method: "POST", path: "/ns/e/keys", bearer: bearer}) }
	expectCode(t, keys(f.grant(f.writer, "user:r", []string{"e"}, []string{"read", "append"}, refusesReads)), 404, "not_found")
	expectPurged(t, keys(f.readerG), head)
}

// v0.49 §8.5, §7.6: a purged namespace's name stays reserved: creating a
// namespace or a branch under it is 412, even as a retry of the request
// that created the purged branch.
func TestV049PurgedNameReserved(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	body := map[string]any{"name": "mb", "at": e.nsHead("m"), "patches": []any{}}
	expect(t, e.branch("m", body, "alice"), 201)
	expect(t, e.branch("m", body, "alice"), 200) // a retry, while it lives
	e.nsPurge("mb")
	expectCode(t, e.branch("m", body, "alice"), 412, "stale")
	expectCode(t, e.branch("m", map[string]any{"name": "mb"}, "bob"), 412, "stale")
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/mb", ifNoneMatch: "*", body: addRoot(map[string]any{}), author: "admin"}), 412, "stale")
}

// v0.49 §8.5, §8.3, §8.6: purges propagated from a base and retention
// prunes skip a purged namespace, whose log ends at its purge-ns entry; a
// purged resource of a live namespace is still 410 "gone".
func TestV049PurgedSkipped(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withoutRetentionLoop)
	e.mkNS("m", map[string]any{"read": "public"})
	a := e.create("m", "a", map[string]any{})
	expect(t, e.branch("m", map[string]any{"name": "mb"}, "alice"), 201)
	expect(t, e.branch("m", map[string]any{"name": "live"}, "alice"), 201)
	head := e.nsPurge("mb")

	// The purge reaches the live branch, not the purged one.
	expect(t, e.purge("m", "a", a, "admin"), 204)
	if lastOf(e.nsKinds("live")) != "purge" {
		t.Fatalf("live branch %v", e.nsKinds("live"))
	}
	if e.nsHead("mb") != head {
		t.Fatalf("purged branch %v", e.nsKinds("mb"))
	}
	// Retention, which only namespaces that aren't branches apply.
	e.mkNS("r", map[string]any{"read": "public", "retention": []any{
		map[string]any{"keep": map[string]any{"revisions": 1}, "archive": false}}})
	revs := e.chain("r", "x", 4)
	rhead := e.nsPurge("r")
	e.clock.Advance(time.Hour)
	rep, err := e.e.ApplyRetention(context.Background())
	if err != nil || len(rep.Errors) > 0 || rep.Checked != 0 || rep.Pruned != 0 {
		t.Fatalf("retention %+v %v", rep, err)
	}
	if e.nsHead("r") != rhead {
		t.Fatalf("purged namespace %v", e.nsKinds("r"))
	}
	expectPurged(t, e.get("/r/r/x/rev/"+revs[0]), rhead)

	// A purged resource of a live namespace is "gone", without head.
	for name, r := range map[string]*resp{
		"read":   e.get("/r/m/a"),
		"append": e.write("PATCH", "m", "a", a, ops(op("add", "/x", 1.0))),
		"create": e.write("PATCH", "m", "a", "", addRoot(map[string]any{})),
		"upload": e.putBlobAs("m", "a", blobID("text/plain", "", []byte("x")), "text/plain", "", []byte("x")),
		"purge":  e.purge("m", "a", a, "admin"),
		"prune":  e.prune("m", "a", map[string]any{"horizon": a}, "admin"),
	} {
		if r.Code != 410 || r.Str("code") != "gone" || r.Obj()["head"] != nil {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
	}
}

// v0.49 §8.5, §G.3: a remote branch purged here no longer follows its
// base's purges: its log ends at its purge-ns entry.
func TestV049RemotePurgeSkipsPurgedBranch(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	f := populateA(t, a)
	expect(t, b.mkRemote("rel", remoteGenesis("main", f.at, nil)), 201)
	head := b.nsPurge("rel")
	expect(t, a.purge("main", "derby", f.lateD, "admin"), 204)
	ctx := context.Background()
	if err := b.e.SyncRemotes(ctx); err != nil {
		t.Fatal(err)
	}
	if b.nsHead("rel") != head {
		t.Fatalf("purged remote branch %v", b.nsKinds("rel"))
	}
	if ns, err := b.e.RemoteNotices(ctx, "rel"); err != nil || len(ns) != 0 {
		t.Fatalf("notices %+v %v", ns, err)
	}
	expectPurged(t, b.get("/r/rel/derby"), head)
}
