package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Tests for the core changes of spec v0.21.

// §6.2 candidate verbs: a PATCH with If-Match passes step 1 with append or
// restore, and step 2 settles the verb from the resource's state, before
// the precondition is compared.
func TestCandidateVerbs(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	appendOnly := e.grant(f.issuer, "user:ap", []string{"sec"}, []string{"read", "append"})
	restoreOnly := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read", "restore"})
	neither := e.grant(f.issuer, "user:n", []string{"sec"}, []string{"read"})

	a := e.create("sec", "a", map[string]any{"v": 1.0}, f.issuerG)
	tomb := e.del("sec", "a", a, f.issuerG)

	// Neither candidate: 403 at step 1.
	expectCode(t, e.write("PATCH", "sec", "a", tomb, []any{}, neither), 403, "forbidden")
	// Append only, on a tombstoned resource: 403, whatever If-Match says
	// (not 410 for a wrong one: the verb is settled first).
	expectCode(t, e.write("PATCH", "sec", "a", tomb, []any{}, appendOnly), 403, "forbidden")
	expectCode(t, e.write("PATCH", "sec", "a", a, []any{}, appendOnly), 403, "forbidden")

	// Restore only restores a tombstoned resource.
	r := e.write("PATCH", "sec", "a", tomb, []any{}, restoreOnly)
	expect(t, r, 201)
	rev := etagOf(r)
	// Once live, restore only is refused, before If-Match is compared: a
	// wrong If-Match still gives 403, not 412.
	expectCode(t, e.write("PATCH", "sec", "a", rev, ops(op("add", "/x", 1.0)), restoreOnly), 403, "forbidden")
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/x", 1.0)), restoreOnly), 403, "forbidden")

	// A retry after a lost response: the entry was a restore, one of the
	// request's candidates, so it answers 200 although the resource is
	// live now.
	r = e.write("PATCH", "sec", "a", tomb, []any{}, restoreOnly)
	expect(t, r, 200)
	if etagOf(r) != rev {
		t.Fatalf("retry answered %s, want %s", etagOf(r), rev)
	}
	// The same principal with append only: the entry's verb isn't a
	// candidate, so no retry; the verb settles as append and the
	// precondition fails.
	appendR := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read", "append"})
	expectCode(t, e.write("PATCH", "sec", "a", tomb, []any{}, appendR), 412, "stale")
	// Another principal gets 412 as before.
	expectCode(t, e.write("PATCH", "sec", "a", tomb, []any{}, f.issuerG), 412, "stale")

	// A purged resource answers 410 whichever the verb.
	expect(t, e.do(req{method: "POST", path: "/r/sec/a/purge", ifMatch: rev, bearer: f.adminG}), 204)
	expectCode(t, e.write("PATCH", "sec", "a", rev, []any{}, appendOnly), 410, "gone")
	expectCode(t, e.write("PATCH", "sec", "a", rev, []any{}, restoreOnly), 410, "gone")
}

// §6.2, §7.5: in a batch, a 403 from settling the verb counts as failing
// authorisation: only those items are reported, and a dry run answers as a
// submit would.
func TestCandidateVerbsBatch(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	restoreOnly := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read", "restore"})
	appendR := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read", "append"})
	batch := func(bearer string, body any, dry bool) *resp {
		p := "/ns/sec/batch"
		if dry {
			p += "?dry-run=1"
		}
		return e.do(req{method: "POST", path: p, body: body, bearer: bearer})
	}
	b := e.create("sec", "b", map[string]any{"v": 1.0}, f.issuerG)
	tombB := e.del("sec", "b", b, f.issuerG)
	c := e.create("sec", "c", map[string]any{"v": 1.0}, f.issuerG)
	d := e.create("sec", "d", map[string]any{"v": 1.0}, f.issuerG)
	tombD := e.del("sec", "d", d, f.issuerG)

	restoreB := map[string]any{"items": []any{map[string]any{"resource": "b", "ifMatch": tombB, "steps": []any{[]any{}}}}}
	// The dry run of a restore-only batch reports its ids.
	r := batch(restoreOnly, restoreB, true)
	expect(t, r, 200)
	// An item that settles as append (c is live) fails authorisation: the
	// dry run answers 403 like a submit, reporting only that item, not d's
	// stale precondition.
	mixed := map[string]any{"items": []any{
		map[string]any{"resource": "c", "ifMatch": c, "steps": []any{ops(op("add", "/x", 1.0))}},
		map[string]any{"resource": "d", "ifMatch": d, "steps": []any{[]any{}}},
	}}
	_ = tombD
	for _, dry := range []bool{true, false} {
		r = batch(restoreOnly, mixed, dry)
		expectCode(t, r, 403, "batch")
		items := r.Obj()["items"].([]any)
		if len(items) != 1 || items[0].(map[string]any)["index"] != 0.0 {
			t.Fatalf("dry=%v: report %s", dry, r.Body)
		}
	}

	// The submit restores b.
	r = batch(restoreOnly, restoreB, false)
	expect(t, r, 201)
	nsID := r.Str("ns_id")
	// Its retry answers 200 with the same batch: the item's recorded verb
	// (restore) is one of its candidates.
	r = batch(restoreOnly, restoreB, false)
	expect(t, r, 200)
	if r.Str("ns_id") != nsID {
		t.Fatalf("retry %s", r.Body)
	}
	// The same principal with append only: no retry, and b is live now, so
	// the verb settles as append and the precondition fails.
	r = batch(appendR, restoreB, false)
	expectCode(t, r, 412, "batch")
}

// §6.2: in a branch, a tombstone read through from the base settles the
// first write as a restore, with that tombstone as its foreign parent.
func TestCandidateVerbsBranch(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	x := e.create("sec", "x", map[string]any{"v": 1.0}, f.issuerG)
	tomb := e.del("sec", "x", x, f.issuerG)
	expect(t, e.branch("sec", map[string]any{"name": "sec-b"}, f.issuerG), 201)
	appendOnly := e.grant(f.issuer, "user:ap", []string{"sec-b"}, []string{"read", "append"})
	restoreOnly := e.grant(f.issuer, "user:r", []string{"sec-b"}, []string{"read", "restore"})
	expectCode(t, e.write("PATCH", "sec-b", "x", tomb, []any{}, appendOnly), 403, "forbidden")
	r := e.write("PATCH", "sec-b", "x", tomb, []any{}, restoreOnly)
	expect(t, r, 201)
	if d := e.doc("sec-b", "x", f.adminG); d["v"] != 1.0 {
		t.Fatalf("restored %v", d)
	}
	// The base is unchanged.
	expectCode(t, e.get("/r/sec/x", f.adminG), 410, "gone")
}

// §6.6: the limit keys of the table, integers in bytes; old names,
// deployment-only keys and size strings are 422.
func TestLimitKeys(t *testing.T) {
	e := newEnv(t)
	mk := func(name string, limits map[string]any) *resp {
		return e.do(req{method: "PATCH", path: "/ns/" + name, ifNoneMatch: "*", author: "admin",
			body: addRoot(map[string]any{"limits": limits})})
	}
	good := map[string]any{
		"patchSetSize": 1024, "opsPerSet": 10, "documentSize": 4096, "nestingDepth": 8,
		"rulesPerNamespace": 4, "rulesPerGrant": 4, "grantSize": 4096, "itemsPerBatch": 10,
		"batchSize": 1 << 20, "branchesPerNamespace": 3, "keepPerResource": 5,
		"ratePerResource": map[string]any{"rate": 1, "burst": 2}, "ratePerPrincipal": map[string]any{"rate": 1, "burst": 2},
		"ratePerNamespace": map[string]any{"rate": 1, "burst": 2}, "retryWindow": "PT5M", "remoteRegistration": "P1D",
	}
	expect(t, mk("good", good), 201)
	for i, bad := range []map[string]any{
		{"liveBranches": 3},             // v0.20 name
		{"remoteBranchLife": "P1D"},     // v0.20 name
		{"logPageSize": 10},             // deployment only
		{"branchDepth": 2},              // deployment only
		{"batchSize": "1 MiB"},          // sizes are integers in bytes
		{"patchSetSize": "1024"},        //
		{"remoteRegistration": 30},      // a duration
		{"ratePerNamespace": 10},        // { rate, burst }
		{"itemsPerBatch": 1.5},          // an integer
		{"documentSize": 64 << 20},      // over the deployment maximum
		{"remoteRegistration": "P400D"}, // over the deployment maximum
	} {
		r := mk("bad", bad)
		if r.Code != 422 {
			t.Fatalf("case %d %v: %d %s", i, bad, r.Code, r.Body)
		}
	}
	// branchesPerNamespace bounds live branches.
	e.mkNS("one", map[string]any{"limits": map[string]any{"branchesPerNamespace": 1}})
	expect(t, e.branch("one", map[string]any{"name": "one-a"}, "alice"), 201)
	expectCode(t, e.branch("one", map[string]any{"name": "one-b"}, "alice"), 422, "limit")
}

// §7.5: the body of a batch is read only up to the principal's batchSize,
// after authentication.
func TestBatchBodyLimit(t *testing.T) {
	f := newAuthFixture(t, map[string]any{
		"limits": map[string]any{"batchSize": 1024},
		"allowances": []any{map[string]any{"sub": "user:bob", "kid": "issuer",
			"itemsPerBatch": 20, "batchSize": 4 << 20}},
	})
	e := f.tenv
	eve := e.grant(f.issuer, "user:eve", []string{"sec"}, []string{"read", "create", "append"})
	big := strings.Repeat("x", 60<<10) // valueSize bounds a string, so three per document
	items := make([]any, 8)            // about 1.6 MB of patch sets
	for i := range items {
		items[i] = map[string]any{"resource": "big-" + string(rune('a'+i)), "ifNoneMatch": "*",
			"steps": []any{addRoot(map[string]any{"a": big, "b": big, "c": big})}}
	}
	body := map[string]any{"items": items}
	post := func(bearer string) *resp {
		return e.do(req{method: "POST", path: "/ns/sec/batch", body: body, bearer: bearer})
	}
	// Authentication comes first: no grant is 401, not 413.
	expect(t, post(""), 401)
	// Over eve's batchSize: 413, without reading on.
	expectCode(t, post(eve), 413, "limit")
	// Within bob's allowance.
	expect(t, post(f.issuerG), 201)
}

// §7.5: item counts are checked at step 4, after authorisation and the
// precondition.
func TestBatchItemCountAtStep4(t *testing.T) {
	f := newAuthFixture(t, map[string]any{"limits": map[string]any{"itemsPerBatch": 2}})
	e := f.tenv
	createOnly := e.grant(f.issuer, "user:c", []string{"sec"}, []string{"read", "create"})
	a := e.create("sec", "a", map[string]any{}, f.issuerG)
	post := func(bearer string, items ...any) *resp {
		return e.do(req{method: "POST", path: "/ns/sec/batch", body: map[string]any{"items": items}, bearer: bearer})
	}
	create := func(name string) any {
		return map[string]any{"resource": name, "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}
	}
	appendA := func(parent string) any {
		return map[string]any{"resource": "a", "ifMatch": parent, "steps": []any{ops(op("add", "/x", 1.0))}}
	}
	// Unauthorised item: 403 before the count.
	expectCode(t, post(createOnly, create("n1"), create("n2"), appendA(a)), 403, "batch")
	// Stale precondition: 412 before the count.
	b := e.appendRev("sec", "a", a, ops(op("add", "/y", 1.0)), f.issuerG)
	expectCode(t, post(f.issuerG, create("n1"), create("n2"), appendA(a)), 412, "batch")
	// All good but too many: 413.
	expectCode(t, post(f.issuerG, create("n1"), create("n2"), appendA(b)), 413, "limit")
	expect(t, post(f.issuerG, create("n1"), appendA(b)), 201)
}

// §7.4, §F.3: /merge is guarded by a * key; merge.authors is validated.
func TestMergeAuthorsGuarded(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	authors := map[string]any{"authors": []any{map[string]any{"sub": "svc:merge", "kid": "ops-2026"}}}
	expectCode(t, e.patchNS("sec", ops(op("add", "/merge", authors)), f.issuerG), 403, "forbidden")
	for _, bad := range []any{
		"svc:merge",
		map[string]any{},
		map[string]any{"authors": []any{map[string]any{"sub": "svc:merge"}}},
		map[string]any{"authors": []any{map[string]any{"sub": "svc:merge", "kid": ""}}},
		map[string]any{"authors": []any{map[string]any{"sub": "svc:merge", "kid": "k", "x": 1}}},
		map[string]any{"authors": []any{}, "other": 1},
	} {
		expectCode(t, e.patchNS("sec", ops(op("add", "/merge", bad)), f.adminG), 422, "invalid")
	}
	expect(t, e.patchNS("sec", ops(op("add", "/merge", authors)), f.adminG), 201)
	// Branch creation is guarded the same way.
	expectCode(t, e.branch("sec", map[string]any{"name": "sec-b", "patches": ops(op("remove", "/merge"))}, f.issuerG), 403, "forbidden")
	expect(t, e.branch("sec", map[string]any{"name": "sec-b", "patches": ops(op("remove", "/merge"))}, f.adminG), 201)
}

// §F.3, §F.6: namespace log entries carry the kid of the key that signed
// the writer's root block, outside the hashed entry.
func TestNSLogKid(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{}, f.issuerG)
	e.appendRev("sec", "a", a, ops(op("add", "/x", 1.0)), f.adminG)
	lg := e.get("/ns/sec/rev/"+e.nsHead("sec", f.adminG)+"/log", f.adminG).Arr()
	n := len(lg)
	if n < 3 {
		t.Fatalf("log %v", lg)
	}
	create, app := lg[n-2].(map[string]any), lg[n-1].(map[string]any)
	if create["author"] != "user:bob" || create["kid"] != "issuer" || app["author"] != "user:root" || app["kid"] != "admin" {
		t.Fatalf("entries %v %v", create, app)
	}

	// Without authentication there is no kid.
	d := newEnv(t)
	d.mkNS("main", map[string]any{})
	d.create("main", "a", map[string]any{})
	for _, x := range d.get("/ns/main/rev/" + d.nsHead("main") + "/log").Arr() {
		if _, has := x.(map[string]any)["kid"]; has {
			t.Fatalf("dev-mode entry with kid: %v", x)
		}
	}
}

// §8.6: retention with "archive": false, and rules without an archive
// where the operator configured none.
func TestRetentionArchiveFalse(t *testing.T) {
	// A rule saying "archive": false applies without an archive, and
	// applying it needs only prune.
	f := newAuthFixture(t, map[string]any{"retention": []any{
		map[string]any{"keep": map[string]any{"revisions": 3}, "archive": false}}}, withoutRetentionLoop)
	e := f.tenv
	pruner := e.grant(f.issuer, "user:p", []string{"sec"}, []string{"read", "create", "append", "prune"})
	revs := e.chain("sec", "a", 6, pruner)
	e.clock.Advance(time.Hour)
	pruner = e.grant(f.issuer, "user:p", []string{"sec"}, []string{"read", "create", "append", "prune"})
	r := e.prune("sec", "a", map[string]any{"horizon": revs[3]}, pruner)
	expect(t, r, 200)
	if r.Str("archive") != "" {
		t.Fatalf("archive: %s", r.Body)
	}
	// Below what the rule keeps still needs a * key.
	expectCode(t, e.prune("sec", "a", map[string]any{"horizon": revs[4]}, pruner), 403, "forbidden")
	// The applier applies it too.
	b := e.chain("sec", "b", 5, pruner)
	e.clock.Advance(time.Hour)
	rep, err := e.e.ApplyRetention(context.Background())
	if err != nil || len(rep.Errors) > 0 || rep.Pruned != 1 {
		t.Fatalf("retention %+v %v", rep, err)
	}
	adminG := e.grant(f.admin, "user:root", []string{"sec"}, allVerbs)
	expectCode(t, e.get("/r/sec/b/rev/"+b[1], adminG), 410, "pruned")
	expect(t, e.get("/r/sec/b/rev/"+b[2], adminG), 200)

	// A rule without archive, and no operator destination: skipped.
	d := newEnv(t, withoutRetentionLoop)
	d.mkNS("tel", map[string]any{"retention": []any{map[string]any{"keep": map[string]any{"revisions": 1}}}})
	c := d.chain("tel", "c", 4)
	d.clock.Advance(time.Hour)
	for range 2 {
		rep, err = d.e.ApplyRetention(context.Background())
		if err != nil || len(rep.Errors) > 0 || rep.Pruned != 0 || rep.Checked != 0 {
			t.Fatalf("retention without archive %+v %v", rep, err)
		}
	}
	expect(t, d.get("/r/tel/c/rev/"+c[0]), 200)

	// "archive": false is 422 in an e2e namespace.
	x := newE2E(t)
	expectCode(t, x.patchNS("e", ops(op("add", "/retention", []any{
		map[string]any{"keep": map[string]any{"revisions": 3}, "archive": false}})), x.adminG), 422, "invalid")
	expect(t, x.patchNS("e", ops(op("add", "/retention", []any{
		map[string]any{"keep": map[string]any{"revisions": 3}}})), x.adminG), 201)
}
