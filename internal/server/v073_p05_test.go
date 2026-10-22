package server

import (
	"fmt"
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

// v0.73 §7.5: the server stops reading a batch body longer than four times
// the larger of the verified principal's batchSize and the deployment
// maximum of documentSize (413 naming batchSize, the principal's as max);
// a body within it is read and judged at step 4.
func TestV073BatchBodyCutOff(t *testing.T) {
	t.Parallel()
	l := core.DefaultLimits()
	l.DocumentSize, l.BatchSize = 64<<10, 2048
	m := l
	m.BatchSize = 1 << 20
	f := newAuthFixture(t, map[string]any{"allowances": []any{map[string]any{"sub": "user:bob", "kid": "issuer", "batchSize": 128 << 10}}},
		func(o *core.Options) { o.Limits, o.Maximums = l, m })
	e := f.tenv
	eve := e.grant(f.issuer, "user:eve", []string{"sec"}, []string{"read", "create"})
	items, size := []any{}, 0
	for i := 0; i < 5; i++ {
		set := addRoot(map[string]any{"s": strings.Repeat("x", 60<<10)})
		size += len(canonical(set))
		items = append(items, map[string]any{"resource": "r" + string(rune('a'+i)), "ifNoneMatch": "*", "steps": []any{set}})
	}
	body := map[string]any{"items": items}
	// About 300 KiB: over 4 × 64 KiB for eve, whose batchSize is 2048…
	expectLimit(t, e.do(req{method: "POST", path: "/ns/sec/batch", body: body, bearer: eve}), 413, "batchSize", -1, 2048)
	// …and within 4 × 128 KiB for bob's allowance: read, and over his
	// batchSize at step 4.
	expectLimit(t, e.do(req{method: "POST", path: "/ns/sec/batch", body: body, bearer: f.issuerG}), 422, "batchSize", int64(size), 128<<10)
}

// v0.73 §6.6 Configurable limits: config writes, a batch's config change,
// a namespace's creation and a branch's patches are held to the patch-set
// and document limits as resource writes are, a creation counting as a
// create, and a config write whose first operation other than test is a
// root replace or add getting documentSize too (Whole documents).
func TestV073ConfigWritesHeldToLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	lim := map[string]any{"patchSetSize": 4096, "documentSize": 16384, "valueSize": 600, "pathSize": 100, "opsPerSet": 40, "nestingDepth": 6}
	e.mkNS("c", map[string]any{"limits": lim})
	pad := func(doc map[string]any, n int) map[string]any {
		for i := 0; i < n; i++ {
			doc[fmt.Sprintf("x-%02d", i)] = strings.Repeat("p", 590)
		}
		return doc
	}
	// A whole document within documentSize, over patchSetSize.
	whole := ops(op("test", "/limits", lim), op("replace", "", pad(map[string]any{"limits": lim}, 12)))
	if n := len(canonical(whole)); n <= 4096 {
		t.Fatalf("a whole document of %d bytes", n)
	}
	expect(t, e.patchNS("c", whole, ""), 201)
	// Any other patch set stays within patchSetSize…
	var adds []map[string]any
	for i := 0; i < 8; i++ {
		adds = append(adds, op("add", fmt.Sprintf("/x-a%d", i), strings.Repeat("a", 590)))
	}
	expectLimit(t, e.patchNS("c", ops(adds...), ""), 422, "patchSetSize", int64(len(canonical(ops(adds...)))), 4096)
	// …and opsPerSet, and the document documentSize, nestingDepth,
	// valueSize and pathSize.
	many := make([]map[string]any, 41)
	for i := range many {
		many[i] = op("add", fmt.Sprintf("/x-m%d", i), 1.0)
	}
	expectLimit(t, e.patchNS("c", ops(many...), ""), 422, "opsPerSet", 41, 40)
	over := ops(op("replace", "", pad(map[string]any{"limits": lim}, 30)))
	expectLimit(t, e.patchNS("c", over, ""), 422, "documentSize", int64(len(canonical(over))), 16384)
	doc := pad(map[string]any{"limits": lim}, 12)
	for i := 0; ; i++ {
		k1, k2 := fmt.Sprintf("x-g%da", i), fmt.Sprintf("x-g%db", i)
		doc[k1], doc[k2] = strings.Repeat("g", 590), strings.Repeat("g", 590)
		r := e.patchNS("c", ops(op("add", "/"+k1, doc[k1]), op("add", "/"+k2, doc[k2])), "")
		if r.Code == 201 {
			continue
		}
		expectLimit(t, r, 422, "documentSize", int64(len(canonical(doc))), 16384)
		break
	}
	deep := map[string]any{"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": map[string]any{"e": []any{1.0}}}}}}
	expectLimit(t, e.patchNS("c", ops(op("add", "/x-deep", deep)), ""), 422, "nestingDepth", 7, 6)
	expectLimit(t, e.patchNS("c", ops(op("add", "/x-v", strings.Repeat("v", 600))), ""), 422, "valueSize", 602, 600)
	expectLimit(t, e.patchNS("c", ops(op("add", "/x-"+strings.Repeat("p", 97), 1.0)), ""), 422, "pathSize", 102, 100)
	// A batch's config change too.
	r := e.batchReq("c", map[string]any{"config": map[string]any{"ifMatch": e.configID("c"), "patches": ops(adds...)}}, "admin")
	expectLimit(t, r, 422, "patchSetSize", int64(len(canonical(ops(adds...)))), 4096)

	// A namespace's creation counts as a create, held to the deployment's
	// documentSize (1 MiB by default).
	big := map[string]any{}
	for i := 0; i < 17; i++ {
		big[fmt.Sprintf("x-%02d", i)] = strings.Repeat("b", 63<<10)
	}
	r = e.do(req{method: "PATCH", path: "/ns/big", ifNoneMatch: "*", author: "admin", body: addRoot(big)})
	expectLimit(t, r, 422, "documentSize", int64(len(canonical(addRoot(big)))), 1<<20)
	delete(big, "x-16")
	delete(big, "x-15")
	expect(t, e.do(req{method: "PATCH", path: "/ns/big", ifNoneMatch: "*", author: "admin", body: addRoot(big)}), 201)

	// A branch's patches and document, held to the base's limits: its
	// patches may be as large as documentSize.
	e.mkNS("b", map[string]any{"limits": lim})
	at := e.nsHead("b")
	padOps := func(n int) []any {
		var out []map[string]any
		for k := range pad(map[string]any{}, n) {
			out = append(out, op("add", "/"+k, strings.Repeat("p", 590)))
		}
		return ops(out...)
	}
	if n := len(canonical(padOps(10))); n <= 4096 {
		t.Fatalf("branch patches of %d bytes", n)
	}
	expect(t, e.branch("b", map[string]any{"name": "b1", "at": at, "patches": padOps(10)}, "alice"), 201)
	r = e.branch("b", map[string]any{"name": "b2", "at": at, "patches": padOps(30)}, "alice")
	expectCode(t, r, 422, "limit")
	if r.Obj()["limit"] != "documentSize" {
		t.Fatalf("branch over documentSize: %s", r.Body)
	}
}

// v0.73 §6.6 Exceeding a limit: for a limit on the resulting document,
// measured is left out for a grant that can't read the resource; for a
// namespace document, for one without unrestricted read.
func TestV073MeasuredLeftOutWithoutRead(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, map[string]any{"limits": map[string]any{"patchSetSize": 4096, "documentSize": 3000, "valueSize": 600, "pathSize": 100}})
	e := f.tenv
	blind := e.grant(f.issuer, "user:blind", []string{"sec"}, []string{"create", "append", "config"})
	reader := e.grant(f.issuer, "user:reader", []string{"sec"}, []string{"read", "create", "append", "config"})
	for _, x := range []struct {
		g        string
		measured bool
	}{{blind, false}, {reader, true}} {
		name := "r-" + map[bool]string{true: "read", false: "blind"}[x.measured]
		head := etagOf(e.write("PATCH", "sec", name, "", addRoot(map[string]any{}), x.g))
		var r *resp
		for i := 0; ; i++ {
			r = e.write("PATCH", "sec", name, head, ops(op("add", fmt.Sprintf("/k%d", i), strings.Repeat("x", 590))), x.g)
			if r.Code != 201 {
				break
			}
			head = etagOf(r)
		}
		for _, r := range []*resp{r, e.write("PATCH", "sec", name, head, ops(op("add", "/v", strings.Repeat("v", 600))), x.g)} {
			expectCode(t, r, 422, "limit")
			if _, has := r.Obj()["measured"]; has != x.measured || r.Obj()["max"] == nil {
				t.Fatalf("%s: measured %v, want %v: %s", name, has, x.measured, r.Body)
			}
		}
		// The patch set's own size is the writer's to know.
		set := ops(op("add", "/big", map[string]any{"a": strings.Repeat("a", 590), "b": strings.Repeat("a", 590), "c": strings.Repeat("a", 590),
			"d": strings.Repeat("a", 590), "e": strings.Repeat("a", 590), "f": strings.Repeat("a", 590), "g": strings.Repeat("a", 590)}))
		expectLimit(t, e.write("PATCH", "sec", name, head, set, x.g), 422, "patchSetSize", int64(len(canonical(set))), 4096)
	}
	// The namespace document: unrestricted read decides.
	cid := e.configID("sec", f.adminG)
	var adds []map[string]any
	for i := 0; i < 5; i++ {
		adds = append(adds, op("add", fmt.Sprintf("/x-%d", i), strings.Repeat("c", 590)))
	}
	for g, measured := range map[string]bool{blind: false, reader: true} {
		r := e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: cid, bearer: g, body: ops(adds...)})
		expectCode(t, r, 422, "limit")
		if _, has := r.Obj()["measured"]; has != measured || r.Obj()["limit"] != "documentSize" {
			t.Fatalf("config write: measured %v, want %v: %s", has, measured, r.Body)
		}
	}
}

// v0.73 §6.6 Values: every namespace's creation, a branch's included, and
// a config write that changes limits or encryption need 3 × (valueSize +
// pathSize) + 1 KiB ≤ patchSetSize, not only an E3 namespace's, which adds
// 36 B × blobsPerDocument.
func TestV073ValuesEveryNamespace(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	mk := func(ns string, patchSetSize int) *resp {
		return e.do(req{method: "PATCH", path: "/ns/" + ns, ifNoneMatch: "*", author: "admin",
			body: addRoot(map[string]any{"limits": map[string]any{"valueSize": 1000, "pathSize": 100, "patchSetSize": patchSetSize}})})
	}
	expectLimit(t, mk("v1", 4323), 422, "patchSetSize", 4324, 4323)
	expect(t, mk("v1", 4324), 201)
	expectLimit(t, e.patchNS("v1", ops(op("replace", "/limits/valueSize", 1001)), ""), 422, "patchSetSize", 4327, 4324)
	expect(t, e.patchNS("v1", ops(op("add", "/x-note", "unrelated")), ""), 201)
	at := e.nsHead("v1")
	r := e.branch("v1", map[string]any{"name": "v1b", "at": at, "patches": ops(op("replace", "/limits/patchSetSize", 4000))}, "alice")
	expectLimit(t, r, 422, "patchSetSize", 4324, 4000)
	expect(t, e.branch("v1", map[string]any{"name": "v1b", "at": at}, "alice"), 201)
}
