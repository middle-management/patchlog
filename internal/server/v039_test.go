package server

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

const (
	gA = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	gB = "bbbbbbbbbbbbbbbbbbbbbbbbbb"
	gC = "cccccccccccccccccccccccccc"
)

// gw is a write with gesture headers (parent "" creates).
func (e *tenv) gw(method, ns, name, parent string, patches []any, hdr map[string]string) *resp {
	e.t.Helper()
	q := req{method: method, path: "/r/" + ns + "/" + name, ifMatch: parent, author: "alice", hdr: hdr}
	if parent == "" {
		q.ifNoneMatch = "*"
	}
	if patches != nil {
		q.body = patches
	}
	return e.do(q)
}

// lastNSEntry is the namespace log's newest entry.
func (e *tenv) lastNSEntry(ns string) map[string]any {
	e.t.Helper()
	lg := e.get("/ns/" + ns + "/rev/" + e.nsHead(ns) + "/log").Arr()
	return lg[len(lg)-1].(map[string]any)
}

// §7.2 (v0.39): Gesture and Undoes on PATCH, DELETE and restore are
// stored with the entry, outside its id, echoed on the response, served by
// both logs, and a retry answers what was first recorded. Anything but one
// gesture id is 400.
func TestV039GestureWrites(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	// Rules don't see gestures (§7.2): a rule refusing gesture gA by an
	// envelope member would refuse the writes below.
	e.mkNS("main", map[string]any{"rules": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/gesture", "value": gA}}}})
	for _, h := range []map[string]string{{"Gesture": "short"}, {"Gesture": strings.ToUpper(gA)}, {"Undoes": gA + "a"}, {"Gesture": ""}, {"Undoes": "aaaaaaaaaaaaaaaaaaaaaaaaa1"}} {
		expectCode(t, e.gw("PATCH", "main", "a", "", addRoot(map[string]any{}), h), 400, "bad_input")
	}
	r := e.gw("PATCH", "main", "a", "", addRoot(map[string]any{"n": 0}), map[string]string{"Gesture": gA})
	expect(t, r, 201)
	a0 := etagOf(r)
	if r.H.Get("Gesture") != gA || r.H.Get("Undoes") != "" || r.Str("gesture") != gA {
		t.Fatalf("create: %v %s", r.H, r.Body)
	}
	if ns := e.lastNSEntry("main"); ns["gesture"] != gA || ns["undoes"] != nil {
		t.Fatalf("ns entry %v", ns)
	}
	// Not part of the id (§3.3): the same genesis without one.
	if b := e.create("main", "b", map[string]any{"n": 0}); b != a0 {
		t.Fatal("the gesture changed the id")
	}
	r = e.gw("PATCH", "main", "a", a0, ops(op("replace", "/n", 1.0)), map[string]string{"Gesture": gB, "Undoes": gA})
	expect(t, r, 201)
	a1 := etagOf(r)
	if r.H.Get("Gesture") != gB || r.H.Get("Undoes") != gA {
		t.Fatalf("append: %v", r.H)
	}
	// A retry with other gestures, or none, is answered as first recorded.
	for _, h := range []map[string]string{{"Gesture": gC}, nil} {
		r = e.gw("PATCH", "main", "a", a0, ops(op("replace", "/n", 1.0)), h)
		expect(t, r, 200)
		if r.H.Get("Gesture") != gB || r.H.Get("Undoes") != gA || r.Str("gesture") != gB {
			t.Fatalf("retry %v: %v %s", h, r.H, r.Body)
		}
	}
	// DELETE and restore; and a DELETE's retry.
	r = e.gw("DELETE", "main", "a", a1, nil, map[string]string{"Gesture": gC})
	expect(t, r, 200)
	tomb := r.Str("tombstone")
	if r.H.Get("Gesture") != gC {
		t.Fatalf("delete %v", r.H)
	}
	if ns := e.lastNSEntry("main"); ns["kind"] != "tombstone" || ns["gesture"] != gC {
		t.Fatalf("tombstone entry %v", ns)
	}
	expectCode(t, e.gw("DELETE", "main", "a", a1, nil, map[string]string{"Undoes": "x"}), 400, "bad_input")
	r = e.gw("DELETE", "main", "a", a1, nil, nil)
	expect(t, r, 200)
	if r.H.Get("Gesture") != gC {
		t.Fatalf("delete retry %v", r.H)
	}
	r = e.gw("PATCH", "main", "a", tomb, []any{}, map[string]string{"Undoes": gC})
	expect(t, r, 201)
	if r.H.Get("Undoes") != gC || r.H.Get("Gesture") != "" {
		t.Fatalf("restore %v", r.H)
	}
	lg := e.get("/r/main/a/rev/" + etagOf(r) + "/log").Arr()
	want := [][2]any{{gA, nil}, {gB, gA}, {gC, nil}, {nil, gC}}
	for i, x := range lg {
		m := x.(map[string]any)
		if m["gesture"] != want[i][0] || m["undoes"] != want[i][1] {
			t.Fatalf("log entry %d: %v", i, m)
		}
	}
	// Exposed to browsers (§7 Browsers): the CORS layer's lists, tested in
	// internal/cors, include Gesture and Undoes.
}

// §7.5 (v0.39): step objects, item and batch defaults, the older step
// forms, and the batch entry's gestures map, left out when no step has one.
func TestV039BatchGestures(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("main", map[string]any{})
	batch := func(body map[string]any) *resp {
		return e.do(req{method: "POST", path: "/ns/main/batch", author: "alice", body: body})
	}
	for i, bad := range []map[string]any{
		{"gesture": "nope", "items": []any{}},
		{"items": []any{map[string]any{"resource": "x", "ifNoneMatch": "*", "undoes": 1, "steps": []any{addRoot(map[string]any{})}}}},
		{"items": []any{map[string]any{"resource": "x", "ifNoneMatch": "*", "steps": []any{map[string]any{"patches": addRoot(map[string]any{}), "delete": true}}}}},
		{"items": []any{map[string]any{"resource": "x", "ifNoneMatch": "*", "steps": []any{map[string]any{"gesture": gA}}}}},
		{"items": []any{map[string]any{"resource": "x", "ifNoneMatch": "*", "steps": []any{map[string]any{"delete": false}}}}},
		{"items": []any{map[string]any{"resource": "x", "ifNoneMatch": "*", "steps": []any{map[string]any{"patches": addRoot(map[string]any{}), "gesture": "A"}}}}},
		{"items": []any{map[string]any{"resource": "x", "ifNoneMatch": "*", "steps": []any{map[string]any{"patches": addRoot(map[string]any{}), "extra": 1}}}}},
		{"items": []any{map[string]any{"resource": "x", "ifNoneMatch": "*", "steps": []any{"remove"}}}},
	} {
		if r := batch(bad); r.Code != 400 {
			t.Fatalf("bad batch %d: %d %s", i, r.Code, r.Body)
		}
	}
	// Without gestures: no member.
	expect(t, batch(map[string]any{"items": []any{map[string]any{"resource": "p", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}), 201)
	if ns := e.lastNSEntry("main"); ns["kind"] != "batch" || ns["gestures"] != nil {
		t.Fatalf("batch without gestures %v", ns)
	}
	p := e.head("main", "p")
	r := batch(map[string]any{"gesture": gA, "items": []any{
		map[string]any{"resource": "p", "ifMatch": p, "steps": []any{
			"delete",
			map[string]any{"patches": []any{}, "gesture": gB, "undoes": gC},
			map[string]any{"delete": true, "undoes": gC},
		}},
		map[string]any{"resource": "q", "ifNoneMatch": "*", "gesture": gB, "steps": []any{addRoot(map[string]any{}), map[string]any{"patches": ops(op("add", "/x", 1.0)), "gesture": gC}}},
	}})
	expect(t, r, 201)
	ns := e.lastNSEntry("main")
	g, _ := ns["gestures"].(map[string]any)
	want := map[string][]map[string]any{
		"p": {{"gesture": gA}, {"gesture": gB, "undoes": gC}, {"gesture": gA, "undoes": gC}},
		"q": {{"gesture": gB}, {"gesture": gC}},
	}
	if len(g) != 2 {
		t.Fatalf("batch gestures %v", ns)
	}
	for res, steps := range want {
		got, _ := g[res].([]any)
		if len(got) != len(steps) {
			t.Fatalf("%s: %v", res, got)
		}
		for i, s := range steps {
			m := got[i].(map[string]any)
			if len(m) != len(s) || m["gesture"] != s["gesture"] || m["undoes"] != s["undoes"] {
				t.Fatalf("%s step %d: %v, want %v", res, i, m, s)
			}
		}
		// The resource log agrees, step by step.
		lg := e.get("/r/main/" + res + "/rev/" + e.headOrTomb("main", res) + "/log").Arr()
		lg = lg[len(lg)-len(steps):]
		for i, s := range steps {
			m := lg[i].(map[string]any)
			if m["gesture"] != s["gesture"] || m["undoes"] != s["undoes"] {
				t.Fatalf("%s log %d: %v, want %v", res, i, m, s)
			}
		}
	}
}

// headOrTomb is a resource's head, or its tombstone.
func (e *tenv) headOrTomb(ns, name string) string {
	e.t.Helper()
	r := e.get("/r/" + ns + "/" + name)
	if r.Code != 302 && r.Code != 410 {
		e.t.Fatalf("head of %s: %d", name, r.Code)
	}
	return etagOf(r)
}

// §7.4 (v0.39): GET /ns/{ns}/gestures/{gesture} lists the namespace's own
// revisions and tombstones written with a gesture or undoing it, oldest
// first, paged with X-Log-Next "{resource}/{id}", no-store; it needs
// unrestricted read, leaves out purged resources and what a branch reads
// through, and keeps working below a pruning horizon (§8.6).
func TestV039GesturesEndpoint(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil, withLogPageSize(2))
	e := f.tenv
	hdr := func(g, u string) map[string]string {
		h := map[string]string{}
		if g != "" {
			h["Gesture"] = g
		}
		if u != "" {
			h["Undoes"] = u
		}
		return h
	}
	wr := func(ns, name, parent string, patches []any, h map[string]string) string {
		q := req{method: "PATCH", path: "/r/" + ns + "/" + name, ifMatch: parent, bearer: f.adminG, body: patches, hdr: h}
		if parent == "" {
			q.ifNoneMatch = "*"
		}
		r := e.do(q)
		expect(t, r, 201)
		return etagOf(r)
	}
	a0 := wr("sec", "a", "", addRoot(map[string]any{"n": 0.0}), hdr(gA, ""))
	a1 := wr("sec", "a", a0, ops(op("replace", "/n", 1.0)), hdr(gA, ""))
	b0 := wr("sec", "b", "", addRoot(map[string]any{}), hdr(gB, gA))
	wr("sec", "c", "", addRoot(map[string]any{}), hdr(gA, ""))
	wr("sec", "z", "", addRoot(map[string]any{}), nil)

	list := func(path, bearer string) ([]any, string) {
		t.Helper()
		r := e.get(path, bearer)
		expect(t, r, 200)
		if r.H.Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control %q", r.H.Get("Cache-Control"))
		}
		return r.Arr(), r.H.Get("X-Log-Next")
	}
	p1, next := list("/ns/sec/gestures/"+gA, f.adminG)
	if len(p1) != 2 || next != "a/"+a1 {
		t.Fatalf("page 1 %v %q", p1, next)
	}
	m := p1[0].(map[string]any)
	if m["resource"] != "a" || m["id"] != a0 || m["kind"] != "rev" || m["gesture"] != gA || m["author"] != "user:root" || m["ns_id"] == nil {
		t.Fatalf("entry %v", m)
	}
	p2, next := list("/ns/sec/gestures/"+gA+"?after="+next, f.adminG)
	if len(p2) != 2 || next != "" || p2[0].(map[string]any)["id"] != b0 || p2[0].(map[string]any)["undoes"] != gA || p2[1].(map[string]any)["resource"] != "c" {
		t.Fatalf("page 2 %v %q", p2, next)
	}
	expectCode(t, e.get("/ns/sec/gestures/"+gA+"?after=a/"+b0, f.adminG), 404, "not_found")
	expectCode(t, e.get("/ns/sec/gestures/NOPE", f.adminG), 400, "bad_input")
	if none, _ := list("/ns/sec/gestures/"+gC, f.adminG); len(none) != 0 {
		t.Fatalf("unknown gesture %v", none)
	}
	// Any reader (v0.46, §7.4), listing only entries of resources its
	// grant may read: a reader limited to some documents finds its own
	// gestures and learns nothing of others, cursors included.
	restricted := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "z"}}}})
	if rp, rnext := list("/ns/sec/gestures/"+gA, restricted); len(rp) != 2 || rnext != "a/"+a1 {
		t.Fatalf("restricted %v %q", rp, rnext)
	}
	only := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	oa, onext := list("/ns/sec/gestures/"+gA, only)
	if len(oa) != 2 || onext != "" || oa[0].(map[string]any)["resource"] != "a" || oa[1].(map[string]any)["resource"] != "a" {
		t.Fatalf("only a: %v %q", oa, onext)
	}
	onlyB := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "b"}}})
	if bp, bnext := list("/ns/sec/gestures/"+gA, onlyB); len(bp) != 1 || bnext != "" || bp[0].(map[string]any)["id"] != b0 {
		t.Fatalf("only b: %v %q", bp, bnext)
	}
	// A cursor naming a resource the reader can't read is unknown.
	expectCode(t, e.get("/ns/sec/gestures/"+gA+"?after=b/"+b0, only), 404, "not_found")
	noRead := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"append"})
	expectCode(t, e.get("/ns/sec/gestures/"+gA, noRead), 404, "not_found")
	expect(t, e.get("/ns/sec/gestures/"+gA), 401)

	// Pruning keeps gestures (§8.6), and the listing still finds them.
	e.clock.Advance(10 * time.Minute)
	expect(t, e.do(req{method: "POST", path: "/r/sec/a/prune", body: map[string]any{"horizon": a1}, bearer: f.adminG}), 200)
	expect(t, e.get("/r/sec/a/rev/"+a1+"/log", f.adminG), 410)
	if pr, _ := list("/ns/sec/gestures/"+gA, f.adminG); len(pr) != 2 || pr[0].(map[string]any)["id"] != a0 || pr[0].(map[string]any)["gesture"] != gA {
		t.Fatalf("after pruning %v", pr)
	}
	// A purged resource is left out.
	expect(t, e.purge("sec", "c", e.head("sec", "c", f.adminG), f.adminG), 204)
	p1, _ = list("/ns/sec/gestures/"+gA, f.adminG)
	p2, _ = list("/ns/sec/gestures/"+gA+"?after=a/"+a1, f.adminG)
	if len(p1)+len(p2) != 3 {
		t.Fatalf("after purge %v %v", p1, p2)
	}
	// A branch lists only its own rows, not what it reads through.
	expect(t, e.branch("sec", map[string]any{"name": "sec-b"}, f.adminG), 201)
	if br, _ := list("/ns/sec-b/gestures/"+gA, f.adminG); len(br) != 0 {
		t.Fatalf("read-through listed %v", br)
	}
	wr("sec-b", "b", b0, ops(op("add", "/x", 1.0)), hdr("", gA))
	if br, _ := list("/ns/sec-b/gestures/"+gA, f.adminG); len(br) != 1 || br[0].(map[string]any)["resource"] != "b" {
		t.Fatalf("branch rows %v", br)
	}
}

// §7.4 (v0.39): the listing isn't offered in sealed namespaces (404,
// after authorisation), and public namespaces answer anyone.
func TestV039GesturesNotOffered(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{}))
	expectCode(t, e.get("/ns/s/gestures/"+gA), 404, "not_offered")
	e.mkNS("pub", map[string]any{"read": "public"})
	expect(t, e.gw("PATCH", "pub", "a", "", addRoot(map[string]any{}), map[string]string{"Gesture": gA}), 201)
	if r := e.get("/ns/pub/gestures/" + gA); r.Code != 200 || len(r.Arr()) != 1 {
		t.Fatalf("public listing %d %s", r.Code, r.Body)
	}
	expect(t, e.get("/ns/nope/gestures/"+gA), 404)
}

// D.2 (v0.39): opening a database from before gestures adds the columns
// and their partial indexes; old entries serve none.
func TestV039GestureMigration(t *testing.T) {
	t.Parallel()
	path, driver := filepath.Join(t.TempDir(), "old.db"), "sqlite"
	if pgtest.Enabled() {
		path, driver = pgtest.NewDB(t), "pgx"
	}
	e := newEnv(t, withPath(path))
	e.mkNS("main", map[string]any{})
	a := e.create("main", "a", map[string]any{})
	e.close()

	dsn := path
	if driver == "sqlite" {
		dsn = "file:" + path
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP INDEX revisions_by_gesture`, `DROP INDEX revisions_by_undoes`,
		`ALTER TABLE revisions DROP COLUMN gesture`, `ALTER TABLE revisions DROP COLUMN undoes`, `ALTER TABLE ns_log DROP COLUMN gestures`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	db.Close()

	e2 := newEnv(t, withPath(path))
	r := e2.gw("PATCH", "main", "a", a, ops(op("add", "/x", 1.0)), map[string]string{"Gesture": gA})
	expect(t, r, 201)
	lg := e2.get("/r/main/a/rev/" + etagOf(r) + "/log").Arr()
	if len(lg) != 2 || lg[0].(map[string]any)["gesture"] != nil || lg[1].(map[string]any)["gesture"] != gA {
		t.Fatalf("log %v", lg)
	}
	if l := e2.get("/ns/main/gestures/" + gA).Arr(); len(l) != 1 {
		t.Fatalf("listing %v", l)
	}
	e2.close()
	db, err = sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	q := `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('revisions_by_gesture', 'revisions_by_undoes')`
	if driver == "pgx" {
		q = `SELECT COUNT(*) FROM pg_indexes WHERE indexname IN ('revisions_by_gesture', 'revisions_by_undoes')`
	}
	var n int
	if err := db.QueryRow(q).Scan(&n); err != nil || n != 2 {
		t.Fatalf("indexes %d %v", n, err)
	}
}

// §G.3 (v0.39): a remote branch mirrors its base's gestures with the
// entries, so its read-through logs serve them as the base does.
func TestV039RemoteBranchGestures(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	a.mkNS("main", map[string]any{"read": "public"})
	r := a.gw("PATCH", "main", "d", "", addRoot(map[string]any{}), map[string]string{"Gesture": gA})
	expect(t, r, 201)
	r = a.gw("PATCH", "main", "d", etagOf(r), ops(op("add", "/x", 1.0)), map[string]string{"Gesture": gB, "Undoes": gA})
	expect(t, r, 201)
	d1 := etagOf(r)
	expect(t, b.mkRemote("rel", remoteGenesis("main", a.nsHead("main"), nil)), 201)
	la := a.get("/r/main/d/rev/" + d1 + "/log").Body
	lb := b.get("/r/rel/d/rev/" + d1 + "/log").Body
	if !strings.Contains(string(lb), `"undoes":"`+gA+`"`) || string(la) != string(lb) {
		t.Fatalf("mirrored log %s, base's %s", lb, la)
	}
}

// §7.3, §7.7 (v0.39): long-polls and event streams serve the same entries
// as log ranges, gestures included.
func TestV039LiveGestures(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	first := e.nsHead("docs")
	r := e.gw("PATCH", "docs", "a", "", addRoot(map[string]any{}), map[string]string{"Gesture": gA})
	expect(t, r, 201)
	a0 := etagOf(r)
	r = e.gw("PATCH", "docs", "a", a0, ops(op("add", "/x", 1.0)), map[string]string{"Gesture": gB, "Undoes": gA})
	expect(t, r, 201)
	a1 := etagOf(r)
	lp := e.get("/ns/docs/log?since=" + first + "&live=long-poll").Arr()
	if len(lp) != 2 || lp[0].(map[string]any)["gesture"] != gA || lp[1].(map[string]any)["undoes"] != gA {
		t.Fatalf("namespace long-poll %v", lp)
	}
	rl := e.get("/r/docs/a/log?since=" + a0 + "&live=long-poll").Arr()
	if len(rl) != 1 || rl[0].(map[string]any)["gesture"] != gB {
		t.Fatalf("resource long-poll %v", rl)
	}
	ch, _, _ := e.openSSE("/r/docs/a/events?since="+a0, nil)
	if ev := next(t, ch); ev.id != a1 || !strings.Contains(ev.data, `"undoes":"`+gA+`"`) {
		t.Fatalf("resource event %v", ev)
	}
	nch, _, _ := e.openSSE("/ns/docs/events?since="+first, nil)
	if ev := next(t, nch); !strings.Contains(ev.data, `"gesture":"`+gA+`"`) {
		t.Fatalf("namespace event %v", ev)
	}
	// A live batch event carries its gestures map.
	expect(t, e.do(req{method: "POST", path: "/ns/docs/batch", author: "alice", body: map[string]any{"undoes": gB,
		"items": []any{map[string]any{"resource": "a", "ifMatch": a1, "steps": []any{ops(op("remove", "/x"))}}}}}), 201)
	next(t, nch)
	if ev := next(t, nch); ev.event != "batch" || !strings.Contains(ev.data, `"gestures":{"a":[{"undoes":"`+gB+`"}]}`) {
		t.Fatalf("batch event %v", ev)
	}
}

// Review fix: a config write is a single write (§7.4), so it MAY carry
// gestures (§7.2): validated, stored with the config entry outside its id,
// echoed on the response, and a retry answers what was recorded.
func TestReviewGesturesOnConfigWrite(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	cfg0 := e.configID("m")
	g, u := reviewGesture(1), reviewGesture(2)
	change := ops(op("add", "/x-note", "n"))
	r := e.do(req{method: "PATCH", path: "/ns/m", ifMatch: cfg0, body: change, author: "admin",
		hdr: map[string]string{"Gesture": g, "Undoes": u}})
	expect(t, r, 201)
	if r.H.Get("Gesture") != g || r.H.Get("Undoes") != u {
		t.Fatalf("echo %q %q", r.H.Get("Gesture"), r.H.Get("Undoes"))
	}
	// The entry carries them; the config id does not depend on them.
	var found bool
	for _, en := range e.nsLog("m") {
		if en["kind"] != "config" {
			continue
		}
		if en["target"] == r.H.Get("X-Config-Revision") {
			found = true
			if en["gesture"] != g || en["undoes"] != u {
				t.Fatalf("entry %v", en)
			}
		}
	}
	if !found {
		t.Fatal("the gesture config entry is not in the log")
	}
	// A retry with a different gesture answers with what was recorded.
	r3 := e.do(req{method: "PATCH", path: "/ns/m", ifMatch: cfg0, body: change, author: "admin",
		hdr: map[string]string{"Gesture": reviewGesture(4)}})
	expect(t, r3, 200)
	if r3.H.Get("Gesture") != g || r3.H.Get("Undoes") != u {
		t.Fatalf("replay echoes what was recorded: %q %q", r3.H.Get("Gesture"), r3.H.Get("Undoes"))
	}
	// A malformed gesture id is 400.
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/m", ifMatch: r3.H.Get("X-Config-Revision"), body: ops(op("add", "/x-y", 1.0)),
		author: "admin", hdr: map[string]string{"Gesture": "NOT-A-GESTURE!"}}), 400, "bad_input")
}

// reviewGesture builds a distinct 26-base32 gesture id.
func reviewGesture(n int) string {
	s := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaa")
	for i := range s {
		s[i] = byte('a' + (n>>i)&1)
	}
	return string(s)
}
