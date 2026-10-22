package server

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
)

// p15Items returns a batch failure's items by index, each checked to be an
// object.
func p15Items(t *testing.T, r *resp) map[int]map[string]any {
	t.Helper()
	out := map[int]map[string]any{}
	items, _ := r.Obj()["items"].([]any)
	for _, x := range items {
		m, ok := x.(map[string]any)
		if !ok {
			t.Fatalf("item %v is not an object: %s", x, r.Body)
		}
		i, _ := m["index"].(float64)
		out[int(i)] = m
	}
	return out
}

// p15Item checks a batch failure's or dry run's item: its status and
// code ("" for none).
func p15Item(t *testing.T, r *resp, index, status int, code string) map[string]any {
	t.Helper()
	it, ok := p15Items(t, r)[index]
	if !ok {
		t.Fatalf("item %d not reported: %s", index, r.Body)
	}
	got, _ := it["code"].(string)
	if st, _ := it["status"].(float64); int(st) != status || got != code {
		t.Fatalf("item %d: %v %v, want %d %s: %s", index, it["status"], it["code"], status, code, r.Body)
	}
	return it
}

// §6.2 step 2.5, §7.5 (GB-4): a "delete" step right after another is 422
// invalid at step 2.5, in the precondition pass every item goes through,
// not at step 3: the batch's status is the first failing item's in request
// order, and every item failing at step 2.5 is listed. A frozen namespace
// (step 2.4) answers first.
func TestV073P15DoubleDeleteAtStep25(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	a := e.create("m", "a", map[string]any{"n": 1.0})
	b0 := e.create("m", "b", map[string]any{"n": 1.0})
	e.appendRev("m", "b", b0, ops(op("replace", "/n", 2.0)))

	body := map[string]any{"items": []any{
		map[string]any{"resource": "a", "ifMatch": a, "steps": []any{"delete", "delete"}},
		map[string]any{"resource": "b", "ifMatch": b0, "steps": []any{ops(op("replace", "/n", 3.0))}},
	}}
	r := e.batchReq("m", body, "alice")
	expectCode(t, r, 422, "batch")
	p15Item(t, r, 0, 422, "invalid")
	p15Item(t, r, 1, 412, "stale")

	// Request order decides the status: the stale item first gives 412,
	// with both listed.
	body = map[string]any{"items": []any{
		map[string]any{"resource": "b", "ifMatch": b0, "steps": []any{ops(op("replace", "/n", 3.0))}},
		map[string]any{"resource": "a", "ifMatch": a, "steps": []any{"delete", "delete"}},
	}}
	r = e.batchReq("m", body, "alice")
	expectCode(t, r, 412, "batch")
	p15Item(t, r, 0, 412, "stale")
	p15Item(t, r, 1, 422, "invalid")

	// Within one item the delete-delete comes before a stale ifMatch
	// (F-G1), which depends on the resource's state.
	r = e.batchReq("m", map[string]any{"items": []any{
		map[string]any{"resource": "b", "ifMatch": b0, "steps": []any{"delete", "delete"}},
	}}, "alice")
	expectCode(t, r, 422, "batch")
	p15Item(t, r, 0, 422, "invalid")

	// A dry run reports it the same way and checks the rest.
	r = e.do(req{method: "POST", path: "/ns/m/batch?dry-run=1", body: map[string]any{"items": []any{
		map[string]any{"resource": "a", "ifMatch": a, "steps": []any{"delete", "delete"}},
	}}, author: "alice"})
	expect(t, r, 200)
	p15Item(t, r, 0, 422, "invalid")

	// Frozen (step 2.4) comes first.
	expect(t, e.patchNS("m", ops(op("add", "/frozen", true)), ""), 201)
	r = e.batchReq("m", map[string]any{"items": []any{
		map[string]any{"resource": "a", "ifMatch": a, "steps": []any{"delete", "delete"}},
	}}, "alice")
	expectCode(t, r, 409, "frozen")
}

// §7.5, §12.1 (GB-5): a batch item under ifNoneMatch whose first step is
// "delete" is 428 at step 2.5, whatever the resource's state; step 1 still
// checks the delete verb.
func TestV073P15DeleteUnderIfNoneMatchItem(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k := newKey("k")
	e.mkNS("m", map[string]any{"read": "public", "keys": []any{k.entry("create", "append", "delete", "restore")}})
	all := e.grant(k, "alice", []string{"m"}, []string{"create", "append", "delete", "restore"})
	noDelete := e.grant(k, "bob", []string{"m"}, []string{"create", "append", "restore"})
	e.create("m", "a", map[string]any{"n": 1.0}, all)
	d := e.create("m", "d", map[string]any{"n": 1.0}, all)
	e.del("m", "d", d, all)

	for _, name := range []string{"a", "missing", "d"} {
		r := e.batchReq("m", map[string]any{"items": []any{
			map[string]any{"resource": name, "ifNoneMatch": "*", "steps": []any{"delete"}},
		}}, all)
		expectCode(t, r, 428, "batch")
		p15Item(t, r, 0, 428, "precondition_required")
	}
	// Without delete: 403 at step 1.
	r := e.batchReq("m", map[string]any{"items": []any{
		map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{"delete"}},
	}}, noDelete)
	expectCode(t, r, 403, "batch")
	p15Item(t, r, 0, 403, "forbidden")
}

// §7.5, §12.1 (GB-6): DELETE with If-None-Match: * is 428 after
// authorisation: 403 without delete, and 410 purged in a purged namespace
// first.
func TestV073P15DeleteWithIfNoneMatch(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k := newKey("k")
	e.mkNS("m", map[string]any{"read": "public", "keys": []any{k.entry("*")}})
	all := e.grant(k, "alice", []string{"m"}, []string{"create", "append", "delete", "restore"})
	noDelete := e.grant(k, "bob", []string{"m"}, []string{"create", "append", "restore"})
	e.create("m", "a", map[string]any{"n": 1.0}, all)

	del := func(name, who string) *resp {
		return e.do(req{method: "DELETE", path: "/r/m/" + name, ifNoneMatch: "*", bearer: who})
	}
	expectCode(t, del("a", all), 428, "precondition_required")
	expectCode(t, del("missing", all), 428, "precondition_required")
	expectCode(t, del("a", noDelete), 403, "forbidden")

	// A purged namespace answers 410 purged before.
	f := newEnv(t)
	f.mkNS("p", map[string]any{"read": "public"})
	f.create("p", "a", map[string]any{})
	head := f.nsPurge("p")
	expectPurged(t, f.do(req{method: "DELETE", path: "/r/p/a", ifNoneMatch: "*", author: "alice"}), head)
}

// §C.2 item 2, §6.2 (GB-7): a PATCH, or a batch item whose first step is a
// patch set, without a precondition checks create, append and restore at
// step 1 and passes if any does, so a create-only grant gets the 428 of
// step 2.5, and a grant with none of them the first refusal (403).
func TestV073P15NoPreconditionCandidates(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k := newKey("k")
	e.mkNS("m", map[string]any{"read": "public", "keys": []any{k.entry("*")}})
	createOnly := e.grant(k, "alice", []string{"m"}, []string{"create"})
	restoreOnly := e.grant(k, "carol", []string{"m"}, []string{"restore"})
	readOnly := e.grant(k, "bob", []string{"m"}, []string{"read"})
	patches := addRoot(map[string]any{"n": 1.0})

	patch := func(who string) *resp {
		return e.do(req{method: "PATCH", path: "/r/m/a", body: patches, bearer: who})
	}
	expectCode(t, patch(createOnly), 428, "precondition_required")
	expectCode(t, patch(restoreOnly), 428, "precondition_required")
	r := patch(readOnly)
	expectCode(t, r, 403, "forbidden")

	item := map[string]any{"items": []any{map[string]any{"resource": "a", "steps": []any{patches}}}}
	r = e.batchReq("m", item, createOnly)
	expectCode(t, r, 428, "batch")
	p15Item(t, r, 0, 428, "precondition_required")
	r = e.batchReq("m", item, readOnly)
	expectCode(t, r, 403, "batch")
	p15Item(t, r, 0, 403, "forbidden")

	// A delete without a precondition has its one verb.
	r = e.do(req{method: "DELETE", path: "/r/m/a", bearer: createOnly})
	expectCode(t, r, 403, "forbidden")
}

// §7.2, §8.1, §12.1 (GB-55): on a tombstoned resource a create is 410 gone
// with head the tombstone, never 412; an append on another head and a
// DELETE are 410 gone with head (not tombstone). The retry lookup still
// runs first, and the head pointer's 410 keeps its members.
func TestV073P15TombstoneWrites(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	genesis := addRoot(map[string]any{"n": 1.0})
	r := e.write("PATCH", "m", "a", "", genesis)
	expect(t, r, 201)
	a0 := etagOf(r)
	a1 := e.appendRev("m", "a", a0, ops(op("replace", "/n", 2.0)))
	tomb := e.del("m", "a", a1)

	expectGone := func(name string, r *resp) {
		t.Helper()
		expectCode(t, r, 410, "gone")
		if r.Str("head") != tomb {
			t.Fatalf("%s: head %q, want the tombstone %s: %s", name, r.Str("head"), tomb, r.Body)
		}
		if _, has := r.Obj()["tombstone"]; has {
			t.Fatalf("%s: a write's 410 names the tombstone as head only: %s", name, r.Body)
		}
	}
	expectGone("create", e.write("PATCH", "m", "a", "", addRoot(map[string]any{"n": 9.0})))
	expectGone("append on an older head", e.write("PATCH", "m", "a", a0, ops(op("replace", "/n", 3.0))))
	expectGone("delete of the tombstone", e.write("DELETE", "m", "a", tomb, nil))
	expectGone("delete of an older head", e.write("DELETE", "m", "a", a0, nil))

	// In a batch too.
	br := e.batchReq("m", map[string]any{"items": []any{
		map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"n": 9.0})}},
	}}, "alice")
	expectCode(t, br, 410, "batch")
	if it := p15Item(t, br, 0, 410, "gone"); it["head"] != tomb {
		t.Fatalf("batch create on a tombstone: %s", br.Body)
	}

	// The retry of the original create still answers 200.
	r = e.write("PATCH", "m", "a", "", genesis)
	expect(t, r, 200)
	if etagOf(r) != a0 {
		t.Fatalf("create retry: %s %v", r.Body, r.H)
	}
	// The head pointer's 410 is unchanged.
	g := e.get("/r/m/a")
	expectCode(t, g, 410, "gone")
	if g.Str("tombstone") != tomb || g.Str("last") != a1 {
		t.Fatalf("head pointer 410: %s", g.Body)
	}
}

// §12.1 (GB-56): a 412 stale names head where there is one, and leaves it
// out where there is none: no head: null.
func TestV073P15StaleWithoutHead(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	a := e.create("m", "a", map[string]any{})
	r := e.write("PATCH", "m", "missing", a, ops(op("add", "/x", 1.0)))
	expectCode(t, r, 412, "stale")
	if _, has := r.Obj()["head"]; has {
		t.Fatalf("412 on a resource without a head carries head: %s", r.Body)
	}
	r = e.batchReq("m", map[string]any{"items": []any{
		map[string]any{"resource": "missing", "ifMatch": a, "steps": []any{"delete"}},
	}}, "alice")
	expectCode(t, r, 412, "batch")
	if _, has := p15Item(t, r, 0, 412, "stale")["head"]; has {
		t.Fatalf("batch 412 on a resource without a head carries head: %s", r.Body)
	}
	// One with a head names it.
	r = e.write("PATCH", "m", "a", hashID(t, "", []byte("x")), ops(op("add", "/x", 1.0)))
	expectCode(t, r, 412, "stale")
	if r.Str("head") != a {
		t.Fatalf("412 head: %s", r.Body)
	}
}

// §7.2, §7.5 (GR-21): an idempotent retry answers 200 only for the same
// principal, the same root sub and kid; a grant from another key with the
// same sub gets 412, for a single write and a batch alike.
func TestV073P15RetrySameRootKid(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k1, k2 := newKey("k1"), newKey("k2")
	e.mkNS("m", map[string]any{"read": "public", "keys": []any{k1.entry("*"), k2.entry("*")}})
	can := []string{"create", "append", "delete", "restore"}
	g1 := e.grant(k1, "alice", []string{"m"}, can)
	g1b := e.grant(k1, "alice", []string{"m"}, can, map[string]any{"exp": e.clock.Now().Add(2 * time.Hour).Format(time.RFC3339)})
	g2 := e.grant(k2, "alice", []string{"m"}, can)

	genesis := addRoot(map[string]any{"n": 1.0})
	r := e.write("PATCH", "m", "a", "", genesis, g1)
	expect(t, r, 201)
	a0 := etagOf(r)
	e.appendRev("m", "a", a0, ops(op("replace", "/n", 2.0)), g1)

	expectCode(t, e.write("PATCH", "m", "a", "", genesis, g2), 412, "stale")
	// Another grant under the same key and sub is the same principal.
	r = e.write("PATCH", "m", "a", "", genesis, g1b)
	expect(t, r, 200)
	if etagOf(r) != a0 {
		t.Fatalf("retry: %v", r.H)
	}

	batch := map[string]any{"items": []any{
		map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{genesis}},
	}}
	expect(t, e.batchReq("m", batch, g1), 201)
	r = e.batchReq("m", batch, g2)
	expectCode(t, r, 412, "batch")
	p15Item(t, r, 0, 412, "stale")
	expect(t, e.batchReq("m", batch, g1b), 200)
}

// §7.2 (GR-21): an entry written while authentication was disabled records
// no grant, and matches a retry on its author once authentication is on;
// another sub gets 412.
func TestV073P15RetryOfUnauthenticatedEntry(t *testing.T) {
	t.Parallel()
	k := newKey("k")
	e, reopen := v073Reopenable(t)
	e.mkNS("m", map[string]any{"read": "public", "keys": []any{k.entry("*")}})
	genesis := addRoot(map[string]any{"n": 1.0})
	a0 := e.create("m", "a", map[string]any{"n": 1.0}, "alice")
	batch := map[string]any{"items": []any{
		map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{genesis}},
	}}
	expect(t, e.batchReq("m", batch, "alice"), 201)

	var priv ed25519.PrivateKey
	e = reopen(withAuth(&priv))
	can := []string{"create", "append", "delete", "restore"}
	alice, bob := e.grant(k, "alice", []string{"m"}, can), e.grant(k, "bob", []string{"m"}, can)
	r := e.write("PATCH", "m", "a", "", genesis, alice)
	expect(t, r, 200)
	if etagOf(r) != a0 {
		t.Fatalf("retry by its author: %v", r.H)
	}
	expect(t, e.batchReq("m", batch, alice), 200)
	expectCode(t, e.write("PATCH", "m", "a", "", genesis, bob), 412, "stale")
	expectCode(t, e.batchReq("m", batch, bob), 412, "batch")
}

// §7.2, §7.6 (GB-37): the retry lookup looks only at the resource's log in
// the namespace written: in a branch, a write whose id matches an entry
// the base holds, read through, by the same author is 412, not 200.
func TestV073P15BranchRetryNotReadThrough(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("main", map[string]any{"read": "public"})
	a0 := e.create("main", "a", map[string]any{"n": 1.0})
	next := ops(op("replace", "/n", 2.0))
	a1 := e.appendRev("main", "a", a0, next)
	expect(t, e.branch("main", map[string]any{"name": "rel"}, "alice"), 201)

	r := e.write("PATCH", "rel", "a", a0, next)
	expectCode(t, r, 412, "stale")
	if r.Str("head") != a1 {
		t.Fatalf("412 head: %s", r.Body)
	}
	r = e.batchReq("rel", map[string]any{"items": []any{
		map[string]any{"resource": "a", "ifMatch": a0, "steps": []any{next}},
	}}, "alice")
	expectCode(t, r, 412, "batch")
	p15Item(t, r, 0, 412, "stale")
}

// §6.2 step 3 (GB-8): a create's patches apply to the document null:
// test "" null and a root replace work, and the genesis folds onto null
// when the document is read back from storage. A create that writes
// nothing, [] or only tests, makes no document and is 422 invalid, as
// before; one that writes null stores the document null, as an add of
// null did (F-G3).
func TestV073P15CreateAppliesToNull(t *testing.T) {
	t.Parallel()
	e, reopen := v073Reopenable(t)
	e.mkNS("m", map[string]any{"read": "public"})
	genesis := ops(op("test", "", nil), op("add", "", map[string]any{"n": 1.0}), op("add", "/m", 2.0))
	r := e.write("PATCH", "m", "a", "", genesis)
	expect(t, r, 201)
	a0 := etagOf(r)
	if a0 != hashID(t, "", canonical(genesis)) {
		t.Fatalf("genesis id %s", a0)
	}
	a1 := e.appendRev("m", "a", a0, ops(op("replace", "/n", 3.0)))
	expect(t, e.write("PATCH", "m", "b", "", ops(op("replace", "", map[string]any{"b": true}))), 201)
	expect(t, e.write("PATCH", "m", "n", "", ops(op("replace", "", nil))), 201)

	for name, patches := range map[string][]any{
		"empty":     {},
		"test only": ops(op("test", "", nil)),
	} {
		r := e.write("PATCH", "m", "c", "", patches)
		expectCode(t, r, 422, "invalid")
		if r.Obj()["index"] != float64(len(patches)) {
			t.Fatalf("%s: %s", name, r.Body)
		}
	}
	expectCode(t, e.write("PATCH", "m", "c", "", ops(op("test", "", map[string]any{}), op("add", "", map[string]any{}))), 422, "invalid")

	// Read back from storage alone: the genesis folds onto null.
	e = reopen()
	for id, want := range map[string]string{a0: `{"m":2,"n":1}`, a1: `{"m":2,"n":3}`} {
		g := e.get("/r/m/a/rev/" + id)
		expect(t, g, 200)
		if string(canonical(g.Obj())) != want {
			t.Fatalf("%s: %s, want %s", id, g.Body, want)
		}
	}
	if d := e.doc("m", "b"); d["b"] != true {
		t.Fatalf("b: %v", d)
	}
	g := e.get("/r/m/n/rev/" + e.head("m", "n"))
	if expect(t, g, 200); string(g.Body) != "null" {
		t.Fatalf("n: %s", g.Body)
	}
}

// §7.5 (GB-28): at step 4 the batch limits come first, then the local
// source's check (422 source), then each item's own limits.
func TestV073P15SourceBeforeItemLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public", "limits": map[string]any{"opsPerSet": 1}})
	e.mkNS("rel", map[string]any{"read": "public"})
	items := []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{
		ops(op("add", "", map[string]any{}), op("add", "/x", 1.0)),
	}}}
	r := e.batchReq("m", map[string]any{"items": items}, "alice")
	expectItemLimit(t, r, 422, "opsPerSet", 2, 1)
	r = e.batchReq("m", map[string]any{"items": items, "source": map[string]any{"ns": "rel", "at": hashID(t, "", []byte("x"))}}, "alice")
	expectCode(t, r, 422, "source")
	if _, has := r.Obj()["items"]; has {
		t.Fatalf("a refused source is answered without items: %s", r.Body)
	}
	// The batch limits still come first.
	many := append(append([]any{}, items...), map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}})
	e.mkNS("two", map[string]any{"read": "public", "limits": map[string]any{"itemsPerBatch": 1}})
	r = e.batchReq("two", map[string]any{"items": many, "source": map[string]any{"ns": "rel", "at": hashID(t, "", []byte("x"))}}, "alice")
	expectLimit(t, r, 422, "itemsPerBatch", 2, 1)
}

// §7.5, §12.1 (GB-30): a source.origin equal to this deployment's own is
// 422 code source, for any caller, without items.
func TestV073P15SourceOwnOrigin(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k := newKey("k")
	e.mkNS("m", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	e.mkNS("rel", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	writer := e.grant(k, "alice", []string{"m"}, []string{"create"})
	items := []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}
	src := map[string]any{"origin": "https://cms.example", "ns": "rel", "at": hashID(t, "", []byte("x"))}
	r := e.batchReq("m", map[string]any{"items": items, "source": src}, writer)
	expectCode(t, r, 422, "source")
	if _, has := r.Obj()["items"]; has {
		t.Fatalf("answered with items: %s", r.Body)
	}
}

// §6.2 step 3, §G.3 (GB-8): a remote branch folds what it reads through
// from its base's deployment as that deployment applied it: a genesis
// onto the document null.
func TestV073P15RemoteGenesisOnNull(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	a.mkNS("main", map[string]any{"read": "public"})
	r := a.write("PATCH", "main", "p", "", ops(op("test", "", nil), op("add", "", map[string]any{"n": 1.0}), op("add", "/m", 2.0)))
	expect(t, r, 201)
	p0 := etagOf(r)
	a.appendRev("main", "p", p0, ops(op("replace", "/n", 3.0)))
	expect(t, b.mkRemote("rel", remoteGenesis("main", a.nsHead("main"), nil)), 201)
	if d := b.doc("rel", "p"); string(canonical(d)) != `{"m":2,"n":3}` {
		t.Fatalf("read through: %v", d)
	}
	g := b.get("/r/rel/p/rev/" + p0)
	expect(t, g, 200)
	if string(canonical(g.Obj())) != `{"m":2,"n":1}` {
		t.Fatalf("genesis read through: %s", g.Body)
	}
}

// §6.2 step 3, §8.6 (GB-8): a pruned range whose genesis applies to the
// document null archives, verifies and restores, its snapshots rebuilt by
// folding the genesis onto null.
func TestV073P15ArchiveGenesisOnNull(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	e := newEnv(t, withArchive(t, dir), withoutRetentionLoop)
	e.mkNS("main", map[string]any{"read": "public"})
	r := e.write("PATCH", "main", "a", "", ops(op("test", "", nil), op("add", "", map[string]any{"n": 0.0})))
	expect(t, r, 201)
	revs := []string{etagOf(r)}
	for i := 1; i < 5; i++ {
		revs = append(revs, e.appendRev("main", "a", revs[i-1], ops(op("replace", "/n", float64(i)))))
	}
	e.clock.Advance(time.Hour)
	expect(t, e.prune("main", "a", map[string]any{"horizon": revs[3]}, "admin"), 200)
	verifyArchive(t, filepath.Join(dir, "main", "a", revs[3]+".jsonl"))
	expectCode(t, e.get("/r/main/a/rev/"+revs[1]), 410, "pruned")
	reps, err := archive.Restore(context.Background(), e.e, archive.RestoreOptions{From: archive.URL(dir)})
	if err != nil || len(reps) != 1 || reps[0].Restored != 3 || len(reps[0].Failed) != 0 {
		t.Fatalf("restore %+v %v", reps, err)
	}
	for i, id := range revs {
		d := e.get("/r/main/a/rev/" + id)
		expect(t, d, 200)
		if d.Obj()["n"] != float64(i) {
			t.Fatalf("restored rev %d: %s", i, d.Body)
		}
	}
}

// §7.5 (GB-24): a batch's 201, and its retry's 200, carry the new config
// id as the body's config and X-Config-Revision when the batch has a
// config change; a batch without one carries neither.
func TestV073P15BatchConfigRevision(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	cfg := e.configID("m")
	patches := ops(op("add", "/x-note", "n"))
	body := map[string]any{
		"items":  []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}},
		"config": map[string]any{"ifMatch": cfg, "patches": patches},
	}
	want := hashID(t, cfg, canonical(patches))
	for _, status := range []int{201, 200} {
		r := e.batchReq("m", body, "alice")
		expect(t, r, status)
		if r.Str("config") != want || r.H.Get("X-Config-Revision") != want || r.H.Get("X-Namespace-Revision") != r.Str("ns_id") {
			t.Fatalf("%d: %s %v", status, r.Body, r.H)
		}
	}
	// Only a config change.
	cfg2 := e.configID("m")
	r := e.batchReq("m", map[string]any{"config": map[string]any{"ifMatch": cfg2, "patches": ops(op("add", "/x-other", "o"))}}, "alice")
	expect(t, r, 201)
	if r.H.Get("X-Config-Revision") == "" || r.H.Get("X-Config-Revision") != r.Str("config") {
		t.Fatalf("config-only batch: %s %v", r.Body, r.H)
	}
	// None.
	r = e.batchReq("m", map[string]any{"items": []any{map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}, "alice")
	expect(t, r, 201)
	if _, has := r.H["X-Config-Revision"]; has || r.Obj()["config"] != nil {
		t.Fatalf("batch without a config change: %s %v", r.Body, r.H)
	}
}

// §7.2, §7.5 (GB-25): a dry run answers 200 { items, config? }: an item
// that would pass at 201, and every item at 200 with its ids where a
// submit would be answered as an idempotent retry, its config change at
// 200 with its id. A dry run names no entry: no ns_id, and none of the
// revision headers.
func TestV073P15DryRunShape(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "public"})
	cfg := e.configID("m")
	genesis := addRoot(map[string]any{})
	body := map[string]any{
		"items":  []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{genesis}}},
		"config": map[string]any{"ifMatch": cfg, "patches": ops(op("add", "/x-note", "n"))},
	}
	dry := func(body map[string]any) *resp {
		t.Helper()
		r := e.do(req{method: "POST", path: "/ns/m/batch?dry-run=1", body: body, author: "alice"})
		expect(t, r, 200)
		for _, h := range []string{"X-Namespace-Revision", "X-Config-Revision"} {
			if _, has := r.H[h]; has {
				t.Fatalf("a dry run carries %s: %v", h, r.H)
			}
		}
		if _, has := r.Obj()["ns_id"]; has {
			t.Fatalf("a dry run carries ns_id: %s", r.Body)
		}
		return r
	}
	gid := hashID(t, "", canonical(genesis))
	cid := hashID(t, cfg, canonical(ops(op("add", "/x-note", "n"))))
	r := dry(body)
	it := r.Obj()["items"].([]any)[0].(map[string]any)
	if it["status"] != 201.0 || it["index"] != 0.0 || it["ids"].([]any)[0] != gid {
		t.Fatalf("passing item: %s", r.Body)
	}
	if c, _ := r.Obj()["config"].(map[string]any); c["status"] != 201.0 || c["config"] != cid {
		t.Fatalf("config report: %s", r.Body)
	}

	// Once applied, a dry run reports the retry a submit would answer.
	expect(t, e.batchReq("m", body, "alice"), 201)
	r = dry(body)
	it = r.Obj()["items"].([]any)[0].(map[string]any)
	if it["status"] != 200.0 || it["index"] != 0.0 || it["resource"] != "a" || it["ids"].([]any)[0] != gid {
		t.Fatalf("retried item: %s", r.Body)
	}
	if c, _ := r.Obj()["config"].(map[string]any); c["status"] != 200.0 || c["config"] != cid {
		t.Fatalf("retried config: %s", r.Body)
	}
	// Without a config change too; another author's is no retry.
	items := map[string]any{"items": []any{map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{genesis}}}}
	expect(t, e.batchReq("m", items, "alice"), 201)
	r = dry(items)
	if it := r.Obj()["items"].([]any)[0].(map[string]any); it["status"] != 200.0 || it["ids"].([]any)[0] != gid {
		t.Fatalf("retried item: %s", r.Body)
	}
	if _, has := r.Obj()["config"]; has {
		t.Fatalf("a dry run without a config change reports one: %s", r.Body)
	}
	r = e.do(req{method: "POST", path: "/ns/m/batch?dry-run=1", body: items, author: "bob"})
	expect(t, r, 200)
	p15Item(t, r, 0, 412, "stale")
}

// §7.5 (GB-26): a dry run runs steps 1-6 for its config change and reports
// it as config: on success { status: 201, config } and the items judged
// against what it produces; failing after its step 1, its failure, and the
// items judged against the current configuration; failing step 1, the
// dry run answers as that config write would.
func TestV073P15DryRunConfigReport(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	star, k := newKey("admin"), newKey("k")
	noTitle := map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "config"}},
		"then": []any{map[string]any{"not": map[string]any{"op": "writes", "overlaps": "/x-title"}}},
	}
	e.mkNS("m", map[string]any{"read": "public", "rules": []any{noTitle},
		"keys": []any{star.entry("*"), k.entry("config", "create", "append", "delete", "restore")}})
	admin := e.grant(star, "admin", []string{"m"}, []string{"config", "create", "append"})
	alice := e.grant(k, "alice", []string{"m"}, []string{"config", "create", "append"})
	bob := e.grant(k, "bob", []string{"m"}, []string{"create", "append"})
	cfg := e.configID("m")
	twoOps := []any{map[string]any{"resource": "z", "ifNoneMatch": "*", "steps": []any{ops(op("add", "", map[string]any{}), op("add", "/x", 1.0))}}}
	limit := ops(op("add", "/limits", map[string]any{"opsPerSet": 1}))
	dry := func(ifMatch string, patches []any, who string) *resp {
		t.Helper()
		return e.do(req{method: "POST", path: "/ns/m/batch?dry-run=1", bearer: who, body: map[string]any{
			"items": twoOps, "config": map[string]any{"ifMatch": ifMatch, "patches": patches}}})
	}
	report := func(r *resp, status int, code string) map[string]any {
		t.Helper()
		expect(t, r, 200)
		c, _ := r.Obj()["config"].(map[string]any)
		if c["status"] != float64(status) || (code != "" && c["code"] != code) {
			t.Fatalf("config report: %s, want %d %s", r.Body, status, code)
		}
		return c
	}

	// Success: the id a submit would produce; the item meets the limit the
	// change sets.
	r := dry(cfg, limit, admin)
	if report(r, 201, "")["config"] != hashID(t, cfg, canonical(limit)) {
		t.Fatalf("config id: %s", r.Body)
	}
	p15Item(t, r, 0, 422, "limit")
	if e.configID("m") != cfg {
		t.Fatal("a dry run wrote its config change")
	}
	// Stale: reported, and the item judged against the current document.
	r = dry(hashID(t, "", []byte("x")), limit, admin)
	if report(r, 412, "stale")["config"] != cfg {
		t.Fatalf("stale report: %s", r.Body)
	}
	p15Item(t, r, 0, 201, "")
	// The *-key guard at step 6 is after step 1: reported too.
	r = dry(cfg, limit, alice)
	report(r, 403, "forbidden")
	p15Item(t, r, 0, 201, "")
	// A namespace rule.
	r = dry(cfg, ops(op("add", "/x-title", "T")), alice)
	report(r, 422, "rule")
	p15Item(t, r, 0, 201, "")
	// Step 1: answered as the config write.
	r = dry(cfg, ops(op("add", "/x-note", "n")), bob)
	expectCode(t, r, 403, "forbidden")
	if _, has := r.Obj()["items"]; has {
		t.Fatalf("a step-1 refusal of the config change reports items: %s", r.Body)
	}
}

// §7.5, §8.4, §8.5 (GB-31): a dry run in a purged or a frozen namespace is
// answered as a submit would be, without items.
func TestV073P15DryRunPurgedFrozen(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("p", map[string]any{"read": "public"})
	e.mkNS("f", map[string]any{"read": "public"})
	item := map[string]any{"items": []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}
	head := e.nsPurge("p")
	r := e.do(req{method: "POST", path: "/ns/p/batch?dry-run=1", body: item, author: "alice"})
	expectPurged(t, r, head)
	expect(t, e.patchNS("f", ops(op("add", "/frozen", true), op("add", "/successor", "p")), ""), 201)
	r = e.do(req{method: "POST", path: "/ns/f/batch?dry-run=1", body: item, author: "alice"})
	expectCode(t, r, 409, "frozen")
	if r.Str("successor") != "p" {
		t.Fatalf("frozen: %s", r.Body)
	}
	for _, r := range []*resp{r, e.do(req{method: "POST", path: "/ns/p/batch?dry-run=1", body: item, author: "alice"})} {
		if _, has := r.Obj()["items"]; has {
			t.Fatalf("answered with items: %s", r.Body)
		}
	}
}

// §12.1 (GB-56): a remote registration's renewal (If-Match) with no
// registration to renew is 412 stale without head, not head: null; one
// that has a registration names its latest entry (§G.3).
func TestV073P15RegistrationStaleWithoutHead(t *testing.T) {
	t.Parallel()
	a := newEnv(t, withOrigin(originA))
	a.mkNS("main", map[string]any{"read": "public"})
	a.create("main", "p", map[string]any{"n": 0.0})
	at := a.nsHead("main")
	r := a.register("main", "rel", at, hashID(t, "", []byte("x")), "b")
	expectCode(t, r, 412, "stale")
	if v, has := r.Obj()["head"]; has {
		t.Fatalf("412 without a registration carries head %v: %s", v, r.Body)
	}
	reg := a.register("main", "rel", at, "", "b")
	expect(t, reg, 201)
	r = a.register("main", "rel", at, hashID(t, "", []byte("x")), "b")
	expectCode(t, r, 412, "stale")
	if h := r.Str("head"); h == "" || h != reg.Str("ns_id") {
		t.Fatalf("412 with a registration: head %q, its entry %q: %s", h, reg.Str("ns_id"), r.Body)
	}
}

// §6.6 "Dry runs draw tokens as the submit would" (F-G4): a batch whose
// config change fails after its step 1 (here a failing test op, step 3)
// draws its tokens once its items pass step 1, submitted or dry-run alike:
// one per item, and one for the change unless a * key made it (here
// authentication is off, so star, or bob's grant, which isn't). Once the
// bucket is empty, both are 429, as the config write alone would be.
func TestV073P15ConfigFailureDrawsAlike(t *testing.T) {
	t.Parallel()
	limits := map[string]any{"limits": map[string]any{"ratePerPrincipal": map[string]any{"rate": 0.001, "burst": 4.0}}}
	setups := map[string]func() (e *tenv, ns, who string){
		"star": func() (*tenv, string, string) {
			e := newEnv(t)
			e.mkNS("m", limits)
			return e, "m", "alice"
		},
		"grant": func() (*tenv, string, string) {
			f := newAuthFixture(t, limits)
			return f.tenv, "sec", f.issuerG
		},
	}
	want := map[string]int{"star": 2, "grant": 1} // writes left of 4 after the batch
	for name, setup := range setups {
		for _, dry := range []bool{false, true} {
			e, ns, who := setup()
			batch := map[string]any{
				"config": map[string]any{"ifMatch": e.configID(ns, who), "patches": ops(op("test", "/x-nope", 1.0))},
				"items": []any{
					map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}},
					map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}},
				}}
			send := func() *resp {
				path := "/ns/" + ns + "/batch"
				if dry {
					path += "?dry-run=1"
				}
				q := req{method: "POST", path: path, body: batch}
				if e.auth {
					q.bearer = who
				} else {
					q.author = who
				}
				return e.do(q)
			}
			r := send()
			if dry {
				expect(t, r, 200)
				if c, _ := r.Obj()["config"].(map[string]any); c["status"] != 422.0 || c["code"] != "invalid" {
					t.Fatalf("%s: dry run's config report: %s", name, r.Body)
				}
			} else {
				expectCode(t, r, 422, "invalid")
			}
			left := 0
			for ; left < 10; left++ {
				w := e.write("PATCH", ns, fmt.Sprintf("w%d", left), "", addRoot(map[string]any{}), who)
				if w.Code == 429 {
					break
				}
				expect(t, w, 201)
			}
			if left != want[name] {
				t.Errorf("%s, dry run %v: %d writes left after the batch, want %d", name, dry, left, want[name])
			}
			expectCode(t, send(), 429, "rate")
		}
	}
}
