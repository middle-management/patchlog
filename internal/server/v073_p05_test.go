package server

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// v073Reopenable opens a server on a database that outlives its engine,
// and returns a function that closes it and opens the same database with
// further options: a deployment restarted with other settings.
func v073Reopenable(t *testing.T, opts ...envOpt) (*tenv, func(more ...envOpt) *tenv) {
	t.Helper()
	var path string
	if pgtest.Enabled() {
		path = pgtest.NewDB(t)
	} else {
		path = filepath.Join(t.TempDir(), "test.db")
	}
	blobs := t.TempDir()
	at := func(o *core.Options) { o.Path, o.BlobDir = path, blobs }
	e := newEnv(t, append(append([]envOpt{}, opts...), at)...)
	return e, func(more ...envOpt) *tenv {
		t.Helper()
		e.srv.Close()
		e.e.Close()
		next := newEnv(t, append(append(append([]envOpt{}, opts...), more...), at)...)
		next.clock = e.clock
		return next
	}
}

// v0.73 §6.6: a limit refused at step 4 of §6.2 is 422 code limit, with
// limit, measured and max; 413 is only for refusals before or while a
// request is read (a body cut off, §C.8 grantSize, §7.8 blobs).
func TestV073LimitsAtStep4Are422(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("l", map[string]any{"limits": map[string]any{"patchSetSize": 4096, "documentSize": 8192,
		"valueSize": 600, "pathSize": 100, "itemsPerBatch": 2, "batchSize": 3000}})
	str := strings.Repeat("x", 500)
	head := e.create("l", "r", map[string]any{"a": 1.0})

	// patchSetSize, documentSize, valueSize and pathSize.
	set := ops(op("add", "/b", map[string]any{"a": str, "b": str, "c": str, "d": str, "e": str, "f": str, "g": str, "h": str, "i": str}))
	expectLimit(t, e.write("PATCH", "l", "r", head, set), 422, "patchSetSize", int64(len(canonical(set))), 4096)
	doc := map[string]any{}
	for _, k := range strings.Split("abcdefghijklmnopq", "") {
		doc[k] = str
	}
	expectLimit(t, e.write("PATCH", "l", "big", "", addRoot(doc)), 422, "documentSize", int64(len(canonical(addRoot(doc)))), 8192)
	expectLimit(t, e.write("PATCH", "l", "r", head, ops(op("add", "/v", strings.Repeat("v", 600)))), 422, "valueSize", 602, 600)
	expectLimit(t, e.write("PATCH", "l", "r", head, ops(op("add", "/"+strings.Repeat("p", 99), 1.0))), 422, "pathSize", 102, 100)

	// A batch's item count and size, answered as a single write's, without
	// items (§7.5).
	create := func(name string, v any) any {
		return map[string]any{"resource": name, "ifNoneMatch": "*", "steps": []any{addRoot(v)}}
	}
	r := e.batchReq("l", map[string]any{"items": []any{create("i1", 1.0), create("i2", 2.0), create("i3", 3.0)}}, "alice")
	expectLimit(t, r, 422, "itemsPerBatch", 3, 2)
	if _, has := r.Obj()["items"]; has {
		t.Fatalf("itemsPerBatch with items: %s", r.Body)
	}
	three := map[string]any{"a": str, "b": str, "c": str}
	r = e.batchReq("l", map[string]any{"items": []any{create("s1", three), create("s2", three)}}, "alice")
	expectLimit(t, r, 422, "batchSize", 2*int64(len(canonical(addRoot(three)))), 3000)

	// A config write's patch set.
	cset := ops(op("add", "/x-a", strings.Repeat("a", 590)), op("add", "/x-b", strings.Repeat("b", 590)),
		op("add", "/x-c", strings.Repeat("c", 590)), op("add", "/x-d", strings.Repeat("d", 590)),
		op("add", "/x-e", strings.Repeat("e", 590)), op("add", "/x-f", strings.Repeat("f", 590)), op("add", "/x-g", strings.Repeat("g", 590)))
	expectLimit(t, e.patchNS("l", cset, ""), 422, "patchSetSize", int64(len(canonical(cset))), 4096)
}

// v0.73 §6.6 Deployment defaults and maximums, Allowances: a limit, an
// allowance or a rule count stored before the deployment lowered a
// maximum is held to it, not refused: the namespace stays writable, held
// to the new maximum, and a config write that leaves the value as stored
// passes, while one that sets a value above the maximum is 422 limit.
func TestV073StoredLimitsHeldToLoweredMaximums(t *testing.T) {
	t.Parallel()
	e, reopen := v073Reopenable(t)
	rule := map[string]any{"op": "test", "path": "/action", "exists": true}
	e.mkNS("n", map[string]any{
		"limits":     map[string]any{"documentSize": 3 << 20, "itemsPerBatch": 1000},
		"allowances": []any{map[string]any{"sub": "svc:i", "kid": "k", "itemsPerBatch": 1000, "bucket": map[string]any{"rate": 500, "burst": 1000}}},
		"rules":      []any{map[string]any{"all": []any{rule, rule}}}})
	e = reopen(func(o *core.Options) {
		m := core.DefaultMaximums()
		m.DocumentSize, m.ItemsPerBatch, m.RulesPerNS, m.RatePerNamespace = 1<<20, 10, 2, core.Rate{Rate: 100, Burst: 200}
		o.Maximums = m
	})
	// Writable, under the new maximums.
	e.create("n", "a", map[string]any{"v": 1.0})
	doc := map[string]any{}
	str := strings.Repeat("x", 60<<10)
	for i := 0; i < 20; i++ {
		doc[string(rune('a'+i))] = str
	}
	expectLimit(t, e.write("PATCH", "n", "big", "", addRoot(doc)), 422, "documentSize", int64(len(canonical(addRoot(doc)))), 1<<20)
	for _, who := range []string{"alice", "svc:i"} {
		expectLimit(t, e.batchReq("n", batchOf("b", 11), who), 422, "itemsPerBatch", 11, 10)
	}
	expect(t, e.batchReq("n", batchOf("c", 10), "svc:i"), 201)
	// Config writes that leave what was stored pass, a freeze among them.
	expect(t, e.patchNS("n", ops(op("add", "/x-note", "kept")), ""), 201)
	expect(t, e.patchNS("n", ops(op("add", "/limits/opsPerSet", 100)), ""), 201)
	// One that sets a value above the maximum doesn't.
	expectLimit(t, e.patchNS("n", ops(op("replace", "/limits/documentSize", 2<<20)), ""), 422, "documentSize", 2<<20, 1<<20)
	expectLimit(t, e.patchNS("n", ops(op("replace", "/allowances/0/itemsPerBatch", 500)), ""), 422, "itemsPerBatch", 500, 10)
	// The rules stored over rulesPerNamespace hold until a write changes them.
	expectLimit(t, e.patchNS("n", ops(op("add", "/rules/-", rule)), ""), 422, "rulesPerNamespace", 4, 2)
	expect(t, e.patchNS("n", ops(op("add", "/frozen", true)), ""), 201)
}

// v0.73 §6.6 Allowances: an allowance's bucket never exceeds the
// deployment maximum of ratePerNamespace: 422 limit, naming
// ratePerNamespace (default, F-L3), without sizes, as for rates.
func TestV073AllowanceBucketMaximum(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("a", map[string]any{})
	max := core.DefaultMaximums().RatePerNamespace
	for _, b := range []map[string]any{{"rate": max.Rate + 1, "burst": 1}, {"rate": 1, "burst": max.Burst + 1}} {
		r := e.patchNS("a", ops(op("add", "/allowances", []any{map[string]any{"sub": "svc:i", "kid": "k", "bucket": b}})), "")
		expectLimit(t, r, 422, "ratePerNamespace", -1, -1)
	}
	expect(t, e.patchNS("a", ops(op("add", "/allowances", []any{map[string]any{"sub": "svc:i", "kid": "k",
		"bucket": map[string]any{"rate": max.Rate, "burst": max.Burst}}})), ""), 201)
}

// v0.73 §12.2: rulesPerNamespace counts every rule form, in rules, roles
// and key scopes, nested ones included, and holds every write that changes
// one of them.
func TestV073RulesPerNamespaceCountsForms(t *testing.T) {
	t.Parallel()
	e, reopen := v073Reopenable(t)
	leaf := map[string]any{"op": "test", "path": "/action", "exists": true}
	three := []any{map[string]any{"all": []any{leaf, leaf}}}
	// One rule of three forms is over a bound of 2.
	r := e.do(req{method: "PATCH", path: "/ns/r", ifNoneMatch: "*", author: "admin",
		body: addRoot(map[string]any{"limits": map[string]any{"rulesPerNamespace": 2}, "rules": three})})
	expectLimit(t, r, 422, "rulesPerNamespace", 3, 2)
	// Roles and key scopes count.
	k := newKey("k")
	key := k.entry("read")
	key["rules"] = []any{leaf}
	r = e.do(req{method: "PATCH", path: "/ns/r", ifNoneMatch: "*", author: "admin",
		body: addRoot(map[string]any{"limits": map[string]any{"rulesPerNamespace": 2}, "keys": []any{key},
			"roles": map[string]any{"ed": map[string]any{"can": []any{"read"}, "rules": []any{leaf, leaf}}}})})
	expectLimit(t, r, 422, "rulesPerNamespace", 3, 2)
	e.mkNS("s", map[string]any{"keys": []any{key}, "roles": map[string]any{"ed": map[string]any{"can": []any{"read"}, "rules": three}}})
	// Stored over a lowered maximum: any write but one that changes rule
	// forms passes; a change to a role's or a key's rules is held to it.
	e = reopen(func(o *core.Options) {
		m := core.DefaultMaximums()
		m.RulesPerNS = 3
		o.Maximums = m
	})
	expect(t, e.patchNS("s", ops(op("add", "/x-a", 1.0)), ""), 201)
	expectLimit(t, e.patchNS("s", ops(op("add", "/roles/ed/rules/-", leaf)), ""), 422, "rulesPerNamespace", 5, 3)
	expectLimit(t, e.patchNS("s", ops(op("add", "/keys/0/rules/-", leaf)), ""), 422, "rulesPerNamespace", 5, 3)
	// Brought under the bound in one write.
	expect(t, e.patchNS("s", ops(op("replace", "/roles/ed/rules", []any{leaf})), ""), 201)
}

// v0.73 §7.4 /principal: writer.limits gives grantSize and rulesPerGrant,
// deployment only (§12.2), at the deployment's values, not the defaults.
func TestV073PrincipalGrantLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(o *core.Options) {
		l, m := core.DefaultLimits(), core.DefaultMaximums()
		l.GrantSize, l.RulesPerGrant = 3000, 5
		m.GrantSize, m.RulesPerGrant = 5000, 7
		o.Limits, o.Maximums = l, m
	})
	e.mkNS("p", map[string]any{})
	r := e.get("/ns/p/principal")
	expect(t, r, 200)
	w, _ := r.Obj()["writer"].(map[string]any)
	l, _ := w["limits"].(map[string]any)
	if l["grantSize"] != 5000.0 || l["rulesPerGrant"] != 7.0 {
		t.Fatalf("writer.limits %v", l)
	}
}

// v0.73 §6.6 Values: the E3 inequality holds a namespace's creation and
// the config writes that change limits or encryption, never a stored
// document: an E3 namespace whose configuration a deployment's new
// defaults put over it still loads, takes writes and a freeze, and only a
// write that changes its limits is refused.
func TestV073ValuesNotOnStoredDocuments(t *testing.T) {
	t.Parallel()
	ks := newKeyStore(t)
	e, reopen := v073Reopenable(t, withKeyStore(ks))
	e.mkNS("e3", e2eDoc(map[string]any{}))
	e = reopen(func(o *core.Options) {
		l := core.DefaultLimits()
		l.PatchSetSize = 200 << 10
		o.Limits, o.Maximums = l, core.DefaultMaximums()
	})
	need := 3*(64<<10+2<<10) + 1<<10 + 36*1000
	expectLimit(t, e.patchNS("e3", ops(op("add", "/limits", map[string]any{"opsPerSet": 100})), ""), 422, "patchSetSize", int64(need), 200<<10)
	expect(t, e.patchNS("e3", ops(op("add", "/maxLag", "PT1H")), ""), 201)
	expect(t, e.patchNS("e3", ops(op("add", "/frozen", true)), ""), 201)
	// A creation is held to it.
	expectLimit(t, e.do(req{method: "PATCH", path: "/ns/e4", ifNoneMatch: "*", author: "admin", body: addRoot(e2eDoc(map[string]any{}))}),
		422, "patchSetSize", int64(need), 200<<10)
}
