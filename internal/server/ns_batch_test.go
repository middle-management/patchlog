package server

import (
	"strings"
	"testing"
)

// §7.4 namespace reads and config writes (dev mode).
func TestNamespace(t *testing.T) {
	e := newEnv(t)
	cfg0 := e.mkNS("docs", map[string]any{"read": "public", "x-title": "Docs"})

	// GET /ns: 302 with Location, ETag and X-Config-Revision.
	r := e.get("/ns/docs")
	expect(t, r, 302)
	head := etagOf(r)
	if r.H.Get("Location") != "/ns/docs/rev/"+head || r.H.Get("X-Config-Revision") != cfg0 {
		t.Fatalf("GET /ns headers %v", r.H)
	}
	if r.H.Get("Cache-Control") != ccHead || r.H.Get("Cache-Tag") != "ns:docs" {
		t.Fatalf("GET /ns cache %v", r.H)
	}
	expect(t, e.get("/ns/nope"), 404)
	// GET /ns/rev: the document in force, immutable.
	r = e.get("/ns/docs/rev/" + head)
	expect(t, r, 200)
	if r.Obj()["x-title"] != "Docs" || r.H.Get("X-Config-Revision") != cfg0 || r.H.Get("Cache-Control") != ccImmutable {
		t.Fatalf("GET /ns/rev %s %v", r.Body, r.H)
	}
	expect(t, e.get("/ns/docs/rev/"+hashID(t, "", []byte("x"))), 404)

	// Creating an existing namespace: 412 {config}.
	r = e.do(req{method: "PATCH", path: "/ns/docs", ifNoneMatch: "*", body: addRoot(map[string]any{})})
	expectCode(t, r, 412, "stale")
	if r.Str("config") != cfg0 {
		t.Fatalf("412 body %s", r.Body)
	}
	// Document writes don't move the config id, so If-Match stays valid.
	a := e.create("docs", "a", map[string]any{})
	e.appendRev("docs", "a", a, ops(op("add", "/x", 1.0)))
	if e.configID("docs") != cfg0 {
		t.Fatal("config id moved on a document write")
	}
	patches := ops(op("replace", "/x-title", "Documents"))
	r = e.do(req{method: "PATCH", path: "/ns/docs", ifMatch: cfg0, body: patches, author: "admin"})
	expect(t, r, 201)
	cfg1 := r.H.Get("X-Config-Revision")
	if cfg1 != hashID(t, cfg0, canonical(patches)) {
		t.Fatalf("config id %s is not the revision hash", cfg1)
	}
	nsid := r.H.Get("X-Namespace-Revision")
	if r.H.Get("Location") != "/ns/docs/rev/"+nsid || nsid != e.nsHead("docs") {
		t.Fatalf("config write headers %v", r.H)
	}
	// Retry by the same principal: 200; by another: 412 {config}.
	r = e.do(req{method: "PATCH", path: "/ns/docs", ifMatch: cfg0, body: patches, author: "admin"})
	expect(t, r, 200)
	if r.H.Get("X-Config-Revision") != cfg1 {
		t.Fatalf("config retry %v", r.H)
	}
	r = e.do(req{method: "PATCH", path: "/ns/docs", ifMatch: cfg0, body: patches, author: "eve"})
	expectCode(t, r, 412, "stale")
	if r.Str("config") != cfg1 {
		t.Fatalf("412 %s", r.Body)
	}
	// 428 and 415.
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/docs", body: patches}), 428, "precondition_required")
	expect(t, e.do(req{method: "PATCH", path: "/ns/docs", ct: "application/json", ifMatch: cfg1, body: patches}), 415)
	// Validation against the built-in namespace-document schema.
	expect(t, e.patchNS("docs", ops(op("replace", "/read", "everyone")), ""), 422)
	expect(t, e.patchNS("docs", ops(op("add", "/rules", "nope")), ""), 422)
	expect(t, e.patchNS("docs", ops(op("add", "/keys", []any{map[string]any{"kid": "x"}})), ""), 422)
	expect(t, e.patchNS("docs", ops(op("add", "/base", map[string]any{"ns": "x", "at": nsid})), ""), 422)
	expect(t, e.patchNS("docs", ops(op("add", "/successor", "nope")), ""), 422)
	expect(t, e.patchNS("docs", ops(op("replace", "", []any{})), ""), 422)
	expect(t, e.patchNS("docs", ops(op("add", "/frozen", "yes")), ""), 422)

	// The old revision still serves the old document.
	r = e.get("/ns/docs/rev/" + head)
	if r.Obj()["x-title"] != "Docs" {
		t.Fatalf("old ns revision changed: %s", r.Body)
	}

	// Log with since, and heads.
	all := e.get("/ns/docs/rev/" + e.nsHead("docs") + "/log")
	entries := all.Arr()
	if len(entries) != 4 {
		t.Fatalf("log %s", all.Body)
	}
	first := entries[0].(map[string]any)["id"].(string)
	r = e.get("/ns/docs/rev/" + e.nsHead("docs") + "/log?since=" + first)
	if len(r.Arr()) != 3 {
		t.Fatalf("since %s", r.Body)
	}
	for _, x := range r.Arr() {
		m := x.(map[string]any)
		for _, k := range []string{"id", "prev", "kind", "author", "created"} {
			if m[k] == nil {
				t.Fatalf("ns log entry lacks %s: %v", k, m)
			}
		}
	}
	expect(t, e.get("/ns/docs/rev/"+first+"/log?since="+e.nsHead("docs")), 404)
	expect(t, e.get("/ns/docs/rev/"+first+"/log?since="+hashID(t, "", nil)), 404)
	// Heads as of a namespace revision.
	e.create("docs", "b", map[string]any{})
	e.del("docs", "b", e.head("docs", "b"))
	e.create("docs", "c", map[string]any{})
	r = e.get("/ns/docs/rev/" + e.nsHead("docs") + "/heads")
	expect(t, r, 200)
	items := r.Obj()["items"].([]any)
	got := []string{}
	for _, x := range items {
		m := x.(map[string]any)
		got = append(got, m["resource"].(string)+":"+m["kind"].(string))
	}
	if strings.Join(got, ",") != "a:head,b:tombstone,c:head" {
		t.Fatalf("heads %v", got)
	}
	r = e.get("/ns/docs/rev/" + head + "/heads")
	if len(r.Obj()["items"].([]any)) != 0 {
		t.Fatalf("heads at genesis %s", r.Body)
	}
	r = e.get("/ns/docs/rev/" + e.nsHead("docs") + "/heads?after=a")
	if n := len(r.Obj()["items"].([]any)); n != 2 {
		t.Fatalf("heads after=a %s", r.Body)
	}
}

// §7.5 batches.
func TestBatch(t *testing.T) {
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	derby := e.create("m", "derby", map[string]any{"score": "0-0"})
	cup := e.create("m", "cup", map[string]any{"score": "1-1"})
	semi := e.create("m", "semi", map[string]any{"score": "2-2"})

	s1 := ops(op("replace", "/score", "1-0"))
	s2 := ops(op("replace", "/score", "2-0"))
	final := addRoot(map[string]any{"score": "0-0"})
	body := map[string]any{"items": []any{
		map[string]any{"resource": "derby", "ifMatch": derby, "steps": []any{s1, s2}},
		map[string]any{"resource": "final", "ifNoneMatch": "*", "steps": []any{final}},
		map[string]any{"resource": "cup", "ifMatch": cup, "steps": []any{"delete"}},
		map[string]any{"resource": "semi", "ifMatch": semi, "steps": []any{"delete", []any{}}},
	}}
	// Dry run: 200 with ids, nothing written.
	before := e.nsHead("m")
	r := e.do(req{method: "POST", path: "/ns/m/batch?dry-run=1", body: body, author: "alice"})
	expect(t, r, 200)
	if e.nsHead("m") != before || r.H.Get("Cache-Control") != "no-store" {
		t.Fatal("dry run wrote something")
	}
	dry := r.Obj()["items"]

	r = e.do(req{method: "POST", path: "/ns/m/batch", body: body, author: "alice"})
	expect(t, r, 201)
	nsid := r.Str("ns_id")
	if nsid == "" || r.H.Get("X-Namespace-Revision") != nsid || nsid != e.nsHead("m") {
		t.Fatalf("batch ns id %s %v", r.Body, r.H)
	}
	// The dry-run report adds index and status; the ids are the submit's.
	for i, it := range r.Obj()["items"].([]any) {
		d := dry.([]any)[i].(map[string]any)
		if d["index"] != float64(i) || d["status"] != 200.0 || string(canonical(d["ids"])) != string(canonical(it.(map[string]any)["ids"])) {
			t.Fatalf("dry run %v differs from %v", d, it)
		}
	}
	// Clients can compute the ids in advance.
	d1 := hashID(t, derby, canonical(s1))
	d2 := hashID(t, d1, canonical(s2))
	f1 := hashID(t, "", canonical(final))
	ct := hashID(t, cup, []byte("tombstone"))
	st := hashID(t, semi, []byte("tombstone"))
	sr := hashID(t, st, []byte("[]"))
	want := [][]string{{d1, d2}, {f1}, {ct}, {st, sr}}
	for i, x := range r.Obj()["items"].([]any) {
		m := x.(map[string]any)
		idsGot := m["ids"].([]any)
		if len(idsGot) != len(want[i]) {
			t.Fatalf("item %d ids %v", i, idsGot)
		}
		for j := range idsGot {
			if idsGot[j] != want[i][j] {
				t.Fatalf("item %d id %d: %v want %s", i, j, idsGot[j], want[i][j])
			}
		}
	}
	// One batch entry, with each resource's final entry, verifiable.
	lg := e.get("/ns/m/rev/" + nsid + "/log?since=" + before)
	arr := lg.Arr()
	if len(arr) != 1 {
		t.Fatalf("batch wrote %d ns entries", len(arr))
	}
	be := arr[0].(map[string]any)
	wantEntry := map[string]any{"kind": "batch", "entries": []any{
		map[string]any{"resource": "derby", "kind": "head", "target": d2},
		map[string]any{"resource": "final", "kind": "head", "target": f1},
		map[string]any{"resource": "cup", "kind": "tombstone", "target": ct},
		map[string]any{"resource": "semi", "kind": "head", "target": sr},
	}}
	if be["id"] != hashID(t, before, canonical(wantEntry)) {
		t.Fatalf("batch entry %v", be)
	}
	// Resource logs carry the intermediate revisions; states are right.
	if n := len(e.get("/r/m/derby/rev/" + d2 + "/log").Arr()); n != 3 {
		t.Fatalf("derby log %d", n)
	}
	expect(t, e.get("/r/m/cup"), 410)
	if e.head("m", "semi") != sr || e.doc("m", "semi")["score"] != "2-2" {
		t.Fatal("semi not restored")
	}
	// Idempotent retry of the batch: 200 with that batch.
	e.appendRev("m", "derby", d2, ops(op("replace", "/score", "3-0")), "bob")
	r = e.do(req{method: "POST", path: "/ns/m/batch", body: body, author: "alice"})
	expect(t, r, 200)
	if r.Str("ns_id") != nsid {
		t.Fatalf("batch retry %s", r.Body)
	}
	r = e.do(req{method: "POST", path: "/ns/m/batch", body: body, author: "bob"})
	expectCode(t, r, 412, "batch")

	// All or nothing, reporting the items that failed at the earliest step.
	head := e.nsHead("m")
	dh := e.head("m", "derby")
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "derby", "ifMatch": dh, "steps": []any{ops(op("remove", "/nope"))}}, // fails at step 3
		map[string]any{"resource": "x1", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}},
		map[string]any{"resource": "semi", "ifMatch": semi, "steps": []any{[]any{}}}, // fails at step 2
	}}})
	expectCode(t, r, 412, "batch")
	items := r.Obj()["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("batch failure items %s", r.Body)
	}
	it := items[0].(map[string]any)
	if it["index"] != 2.0 || it["status"] != 412.0 || it["code"] != "stale" || it["head"] != sr {
		t.Fatalf("batch failure item %v", it)
	}
	if e.nsHead("m") != head || e.head("m", "derby") != dh {
		t.Fatal("failed batch wrote something")
	}
	expect(t, e.get("/r/m/x1"), 404)
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "x1", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}},
		map[string]any{"resource": "derby", "ifMatch": dh, "steps": []any{ops(op("remove", "/nope"))}},
	}}})
	expectCode(t, r, 422, "batch")
	if it := r.Obj()["items"].([]any)[0].(map[string]any); it["index"] != 1.0 || it["code"] != "invalid" {
		t.Fatalf("422 batch item %v", it)
	}
	expect(t, e.get("/r/m/x1"), 404)

	// Malformed batches.
	expect(t, e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "x1", "steps": []any{addRoot(map[string]any{})}}}}}), 428)
	expect(t, e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "x1", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}},
		map[string]any{"resource": "x1", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}}), 400)
	expect(t, e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{"items": []any{}}}), 400)
	expect(t, e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "x1", "ifNoneMatch": "*", "steps": []any{"purge"}}}}}), 400)
	// Items per batch limit.
	expect(t, e.patchNS("m", ops(op("add", "/limits", map[string]any{"itemsPerBatch": 1.0})), ""), 201)
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "y1", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}},
		map[string]any{"resource": "y2", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}})
	expectCode(t, r, 413, "limit")
}

// §7.5: config change in a batch, items against the new configuration,
// idempotent retry of a batch with a config change, schemas from earlier items.
func TestBatchConfigAndSchemas(t *testing.T) {
	e := newEnv(t)
	cfg0 := e.mkNS("m", map[string]any{"read": "public"})
	cfgPatches := ops(op("add", "/rules", []any{map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "create"}},
		"then": []any{map[string]any{"op": "test", "path": "/doc/ok", "value": true}},
	}}))
	// An item violating the new rule fails the whole batch, config included.
	r := e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{
		"config": map[string]any{"ifMatch": cfg0, "patches": cfgPatches},
		"items":  []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"ok": false})}}},
	}})
	expectCode(t, r, 422, "batch")
	if e.configID("m") != cfg0 {
		t.Fatal("config changed by a failed batch")
	}
	// A stale config precondition fails the batch.
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{
		"config": map[string]any{"ifMatch": hashID(t, "", nil), "patches": cfgPatches},
		"items":  []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"ok": true})}}},
	}})
	expect(t, r, 412)
	body := map[string]any{
		"config": map[string]any{"ifMatch": cfg0, "patches": cfgPatches},
		"items":  []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"ok": true})}}},
	}
	before := e.nsHead("m")
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: body})
	expect(t, r, 201)
	nsid := r.Str("ns_id")
	cfg1 := hashID(t, cfg0, canonical(cfgPatches))
	if e.configID("m") != cfg1 || r.Str("config") != cfg1 {
		t.Fatalf("config after batch %s, want %s", e.configID("m"), cfg1)
	}
	// The batch entry lists the config change first; one entry in all.
	lg := e.get("/ns/m/rev/" + nsid + "/log?since=" + before).Arr()
	if len(lg) != 1 {
		t.Fatalf("batch with config wrote %d entries", len(lg))
	}
	entries := lg[0].(map[string]any)["entries"].([]any)
	if entries[0].(map[string]any)["kind"] != "config" || entries[0].(map[string]any)["target"] != cfg1 {
		t.Fatalf("batch entries %v", entries)
	}
	// The ns revision of the batch reports the new config.
	if e.get("/ns/m/rev/"+nsid).H.Get("X-Config-Revision") != cfg1 {
		t.Fatal("X-Config-Revision at the batch entry")
	}
	// Idempotent retry of the whole batch, config included.
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: body})
	expect(t, r, 200)
	if r.Str("ns_id") != nsid {
		t.Fatalf("retry %s", r.Body)
	}
	// Config change alone in a batch. Its members are checked as a config
	// write's (§7.4): one that doesn't start with "x-" is refused.
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{
		"config": map[string]any{"ifMatch": cfg1, "patches": ops(op("add", "/title", "x"))}}})
	expectCode(t, r, 422, "invalid")
	if errPointer(t, r) != "/title" {
		t.Fatalf("batch config with an unknown member: %s", r.Body)
	}
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{
		"config": map[string]any{"ifMatch": cfg1, "patches": ops(op("add", "/x-title", "x"))}}})
	expect(t, r, 201)

	// Items may reference schema revisions created by earlier items.
	expect(t, e.patchNS("m", ops(op("remove", "/rules")), ""), 201)
	sdoc := map[string]any{"$schema": dialect, "type": "object", "required": []any{"n"}}
	sid := hashID(t, "", canonical(addRoot(sdoc)))
	ref := "/r/m/s/rev/" + sid
	mk := func(n any) map[string]any {
		return map[string]any{"items": []any{
			map[string]any{"resource": "s", "ifNoneMatch": "*", "steps": []any{addRoot(sdoc)}},
			map[string]any{"resource": "typed", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"$schema": ref, "ok": true, "n": n})}},
		}}
	}
	bad := map[string]any{"items": []any{
		map[string]any{"resource": "s", "ifNoneMatch": "*", "steps": []any{addRoot(sdoc)}},
		map[string]any{"resource": "typed", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"$schema": ref, "ok": true})}},
	}}
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: bad})
	expectCode(t, r, 422, "batch")
	if it := r.Obj()["items"].([]any)[0].(map[string]any); it["index"] != 1.0 || it["code"] != "invalid" {
		t.Fatalf("schema batch failure %s", r.Body)
	}
	// Nothing was written, so the reference is still unavailable outside the batch.
	r = e.write("PATCH", "m", "other", "", addRoot(map[string]any{"$schema": ref, "ok": true, "n": 1.0}))
	expectCode(t, r, 422, "schema_unavailable")
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: mk(1.0)})
	expect(t, r, 201)
	e.create("m", "other", map[string]any{"$schema": ref, "ok": true, "n": 1.0})
	// Frozen namespaces refuse batches with 409.
	expect(t, e.patchNS("m", ops(op("add", "/frozen", true)), ""), 201)
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "z", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"ok": true})}}}}})
	expectCode(t, r, 409, "frozen")
}

// §7.5 source: local sources are checked.
func TestBatchSource(t *testing.T) {
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	e.mkNS("rel", map[string]any{"read": "public"})
	item := []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}
	r := e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{"items": item,
		"source": map[string]any{"ns": "rel", "at": hashID(t, "", nil)}}})
	expect(t, r, 422)
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{"items": item,
		"source": map[string]any{"ns": "rel", "at": e.nsHead("rel"), "origin": "https://cms.example"}}})
	expect(t, r, 422)
	src := map[string]any{"ns": "rel", "at": e.nsHead("rel")}
	r = e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{"items": item, "source": src}})
	expect(t, r, 201)
	lg := e.get("/ns/m/rev/" + r.Str("ns_id") + "/log").Arr()
	last := lg[len(lg)-1].(map[string]any)
	if string(canonical(last["source"])) != string(canonical(src)) {
		t.Fatalf("source not recorded: %v", last)
	}
}

// §7.5 dry run by a principal that has never written.
func TestBatchDryRunNewPrincipal(t *testing.T) {
	e := newEnv(t, withFileDB(t))
	e.mkNS("m", map[string]any{"read": "public"})
	body := map[string]any{"items": []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}
	r := e.do(req{method: "POST", path: "/ns/m/batch?dry-run=1", body: body, author: "newcomer"})
	expect(t, r, 200)
	if ids := r.Obj()["items"].([]any)[0].(map[string]any)["ids"].([]any); ids[0] != hashID(t, "", canonical(addRoot(map[string]any{}))) {
		t.Fatalf("dry run ids %s", r.Body)
	}
	// A dry run reports every item: failed ones with the status and code of
	// the step they failed at, the rest with their ids (§7.5).
	r = e.do(req{method: "POST", path: "/ns/m/batch?dry-run=1", author: "newcomer2", body: map[string]any{"items": []any{
		map[string]any{"resource": "a", "ifMatch": hashID(t, "", nil), "steps": []any{[]any{}}},
		map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{ops(op("add", "/x", 1))}},
		map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}})
	expect(t, r, 200)
	rep := r.Obj()["items"].([]any)
	if len(rep) != 3 {
		t.Fatalf("report %s", r.Body)
	}
	a, b, c := rep[0].(map[string]any), rep[1].(map[string]any), rep[2].(map[string]any)
	if a["index"] != 0.0 || a["status"] != 412.0 || a["code"] != "stale" || b["status"] != 422.0 || b["code"] != "invalid" ||
		c["status"] != 200.0 || c["ids"].([]any)[0] != hashID(t, "", canonical(addRoot(map[string]any{}))) {
		t.Fatalf("report %s", r.Body)
	}
	// Authorisation failures still answer as a submit would (§6.2).
	expect(t, e.do(req{method: "POST", path: "/ns/m/batch", body: body, author: "newcomer"}), 201)
}
