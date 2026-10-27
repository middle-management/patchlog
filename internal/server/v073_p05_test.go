package server

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// v073DB is a database for a test to open, and inspect, by its path.
func v073DB(t *testing.T) string {
	if pgtest.Enabled() {
		return pgtest.NewDB(t)
	}
	return filepath.Join(t.TempDir(), "test.db")
}

// v073Reopenable opens a server on a database that outlives its engine,
// and returns a function that closes it and opens the same database with
// further options: a deployment restarted with other settings.
func v073Reopenable(t *testing.T, opts ...envOpt) (*tenv, func(more ...envOpt) *tenv) {
	t.Helper()
	path, blobs := v073DB(t), t.TempDir()
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

// v0.73 §E.1 Stored digests: a namespace encrypted at rest stores no
// plaintext size or digest of its heads beside the encrypted content, and
// a raise to at-rest clears the ones stored before. /heads leaves them
// out; a revision read still sends Repr-Digest (§7.1), of the document it
// serves.
func TestV073NoStoredDigestsAtRest(t *testing.T) {
	t.Parallel()
	path := v073DB(t)
	e := newSealedEnv(t, withPath(path))
	e.mkNS("r", map[string]any{"read": "public", "encryption": map[string]any{"level": "at-rest"}})
	a := e.create("r", "a", map[string]any{"a": 1.0})
	if n := storedMeta(t, path); n != 0 {
		t.Fatalf("%d revisions at rest store a size or digest", n)
	}
	if it := e.headItems("r", e.nsHead("r"))["a"]; it["created"] == nil || it["size"] != nil || it["digest"] != nil {
		t.Fatalf("at-rest heads %v", it)
	}
	for i := 0; i < 2; i++ { // computed, then from the read cache
		r := e.get("/r/r/a/rev/" + a)
		sum := sha256.Sum256(r.Body)
		if r.Code != 200 || r.H.Get("Repr-Digest") != core.ReprDigest(sum[:]) || r.H.Get("Last-Modified") == "" {
			t.Fatalf("at-rest revision %d %v", r.Code, r.H)
		}
	}

	e.mkNS("p", map[string]any{"read": "public"})
	e.create("p", "b", map[string]any{"b": 1.0})
	if n := storedMeta(t, path); n != 1 {
		t.Fatalf("%d revisions store a size or digest, want the plain head's", n)
	}
	expect(t, e.patchNS("p", ops(op("add", "/encryption", map[string]any{"level": "at-rest"})), ""), 201)
	if n := storedMeta(t, path); n != 0 {
		t.Fatalf("%d revisions store a size or digest after the raise to at-rest", n)
	}
	e.appendRev("p", "b", e.head("p", "b"), ops(op("add", "/c", 2.0)))
	if n := storedMeta(t, path); n != 0 {
		t.Fatalf("%d revisions store a size or digest after a write at rest", n)
	}
}

// v0.73 §C.4: a key scope's attrs schema is held to the rules of a rule's
// schema (§6.4.2), compiled when the namespace document is written: 422
// invalid at /keys/{i}/attrs, not a 403 on every request it verifies.
func TestV073KeyAttrsCompiledAtWrite(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("k", map[string]any{})
	k := newKey("k")
	for _, attrs := range []any{
		map[string]any{"properties": map[string]any{"team": map[string]any{"type": "string", "pattern": "(?=x)"}}}, // lookaround: not RE2
		map[string]any{"$ref": "https://example.com/schema"},                                                       // remote reference
	} {
		key := k.entry("read")
		key["attrs"] = attrs
		r := e.patchNS("k", ops(op("add", "/keys", []any{newKey("other").entry("read"), key})), "")
		expectCode(t, r, 422, "invalid")
		if errs, _ := r.Obj()["errors"].([]any); len(errs) != 1 || errs[0].(map[string]any)["pointer"] != "/keys/1/attrs" {
			t.Fatalf("attrs %v: %s", attrs, r.Body)
		}
	}
	key := k.entry("read")
	key["attrs"] = map[string]any{"required": []any{"team"}, "properties": map[string]any{"team": map[string]any{"pattern": "^[a-z]+$"}}}
	expect(t, e.patchNS("k", ops(op("add", "/keys", []any{key})), ""), 201)
}

// v0.73 §C.4: the revoked message names what a revocation id is, a root
// block's being its grant id.
func TestV073RevokedMessage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("v", map[string]any{})
	r := e.patchNS("v", ops(op("add", "/revoked", []any{"not-an-id"})), "")
	expectCode(t, r, 422, "invalid")
	if !strings.Contains(r.Str("message"), "grant id") {
		t.Fatalf("revoked message %s", r.Body)
	}
}

// v073SQL opens the database at path, a test's own (v073DB), for a test
// to inspect or set rows as an earlier release left them; q's ? are the
// dialect's placeholders.
func v073SQL(t *testing.T, path string) (db *sql.DB, q func(string) string) {
	t.Helper()
	driver, dsn := "sqlite", sqlitedsn.DSN(path, "_pragma=busy_timeout(10000)")
	q = func(s string) string { return s }
	if strings.HasPrefix(path, "postgres") {
		driver, dsn = "pgx", pgtest.DSN(path)
		q = func(s string) string {
			var b strings.Builder
			n := 0
			for _, r := range s {
				if r == '?' {
					n++
					fmt.Fprintf(&b, "$%d", n)
					continue
				}
				b.WriteRune(r)
			}
			return b.String()
		}
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, q
}

// v073Unapplied removes the record of the core's migration name (package
// dbmigrate, under mmmigrate's namespace patchlog) from the database at
// path, a test's own (v073DB), as a database an earlier release wrote
// lacks it: the next open applies it.
func v073Unapplied(t *testing.T, path, name string) {
	t.Helper()
	db, q := v073SQL(t, path)
	table := "mmmigrate_applied"
	if strings.HasPrefix(path, "postgres") {
		table = "mmmigrate.applied"
	}
	r, err := db.Exec(q(`DELETE FROM `+table+` WHERE (namespace = 'patchlog' OR namespace LIKE 'patchlog@%') AND name = ?`), name)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		t.Fatalf("migration %s: %d records (%v), want 1", name, n, err)
	}
}

// v073Epoch is encryption.epoch of a namespace's current document, as
// stored.
func v073Epoch(t *testing.T, path, ns string) float64 {
	t.Helper()
	db, q := v073SQL(t, path)
	var doc string
	if err := db.QueryRow(q(`SELECT c.doc FROM ns_config c JOIN namespaces n ON c.ns = n.ns WHERE n.name = ? ORDER BY c.seq DESC LIMIT 1`), ns).Scan(&doc); err != nil {
		t.Fatal(err)
	}
	enc, _ := jsonv.MustParse([]byte(doc)).(map[string]any)["encryption"].(map[string]any)
	ep, _ := enc["epoch"].(float64)
	return ep
}

// v0.73 §6.6 Values holds a config write that changes limits or
// encryption, but an epoch's rotation changes no term of the inequality,
// and §E.2.1 rotates whenever read access is revoked. A sealed namespace
// whose limits no longer meet the inequality (one an earlier release held
// only at E3, or here a deployment's since lowered default) keeps
// rotating: after a revocation, on schedule and by a config write moving
// its epoch, while a write changing its limits or another encryption
// member is still held to it.
func TestV073EpochRotationNotHeldToValues(t *testing.T) {
	t.Parallel()
	path, blobs := v073DB(t), t.TempDir()
	ks := newKeyStore(t)
	at := func(o *core.Options) { o.Path, o.BlobDir = path, blobs }
	e := newEnv(t, withKeyStore(ks), withEncTuning, at)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	e.srv.Close()
	e.e.Close()
	e = newEnv(t, withKeyStore(ks), withEncTuning, at, func(o *core.Options) {
		o.Limits.PatchSetSize = 64 << 10
		o.RotateOnRevoke = true
	})
	need := int64(3*(64<<10+2<<10) + 1<<10)
	expect(t, e.write("PATCH", "s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0}))), 201)
	expect(t, e.patchNS("s", ops(op("add", "/revoked", []any{"1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})), ""), 201)
	// The document sets no epoch: 1 (§E.2.1), and the rotation adds 2.
	if ep := v073Epoch(t, path, "s"); ep != 2 {
		t.Fatalf("epoch %v after a revocation with -rotate-on-revoke, want 2", ep)
	}
	if ep, err := e.e.RotateEpoch(t.Context(), "s", core.RotateAuthor); err != nil || ep != 3 {
		t.Fatalf("RotateEpoch: %v, %v", ep, err)
	}
	e.clock.Advance(2 * time.Hour)
	if done, err := e.e.RotateDue(t.Context(), time.Hour); err != nil || len(done) != 1 {
		t.Fatalf("RotateDue: %v, %v", done, err)
	}
	expect(t, e.patchNS("s", ops(op("replace", "/encryption/epoch", 5.0)), ""), 201)
	if ep := v073Epoch(t, path, "s"); ep != 5 {
		t.Fatalf("epoch %v, want 5", ep)
	}
	expect(t, e.write("PATCH", "s", "a", e.head("s", "a"), withNonce(ops(op("add", "/w", 2.0)))), 201)
	expectLimit(t, e.patchNS("s", ops(op("add", "/encryption/pad", true)), ""), 422, "patchSetSize", need, 64<<10)
	expectLimit(t, e.patchNS("s", ops(op("replace", "/encryption/epoch", 6.0), op("add", "/limits", map[string]any{"opsPerSet": 100})), ""),
		422, "patchSetSize", need, 64<<10)
}

// v0.73 §6.6: a namespace's own bound, a lowered rulesPerNamespace among
// them, holds its creation, and a branch's creation is a namespace's
// creation. A base stored over the bound still takes other writes, but its
// rule forms don't pass into a new branch, as they don't into a new
// namespace.
func TestV073BranchCreationHeldToRulesPerNamespace(t *testing.T) {
	t.Parallel()
	e, reopen := v073Reopenable(t)
	leaf := map[string]any{"op": "test", "path": "/action", "exists": true}
	roles := map[string]any{"ed": map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"all": []any{leaf, leaf}}, leaf}}} // 4 rule forms
	e.mkNS("s", map[string]any{"roles": roles})
	e = reopen(func(o *core.Options) {
		m := core.DefaultMaximums()
		m.RulesPerNS = 3
		o.Maximums = m
	})
	expect(t, e.patchNS("s", ops(op("add", "/x-a", 1.0)), ""), 201)
	expectLimit(t, e.do(req{method: "PATCH", path: "/ns/n", ifNoneMatch: "*", author: "admin", body: addRoot(map[string]any{"roles": roles})}),
		422, "rulesPerNamespace", 4, 3)
	expectLimit(t, e.branch("s", map[string]any{"name": "sb"}, "alice"), 422, "rulesPerNamespace", 4, 3)
	// Within it once the branch drops a rule form.
	expect(t, e.branch("s", map[string]any{"name": "sb", "patches": ops(op("remove", "/roles/ed/rules/1"))}, "alice"), 201)
}

// v0.73 §6.6: a remote branch's creation, like any namespace's, is held to
// the patch-set and document limits, the creation counting as a create
// (§G.3 creates it by PATCH /ns/{ns} with If-None-Match: *).
func TestV073RemoteBranchCreationHeldToLimits(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, []envOpt{func(o *core.Options) {
		o.Limits = core.DefaultLimits()
		o.Limits.DocumentSize = 4096
	}})
	a.mkNS("main", map[string]any{"read": "public"})
	a.create("main", "d", map[string]any{"d": 1.0})
	at := a.nsHead("main")
	big := remoteGenesis("main", at, map[string]any{"x-note": strings.Repeat("x", 5000)})
	expectLimit(t, b.mkRemote("rel", big), 422, "documentSize", int64(len(canonical(big))), 4096)
	expect(t, b.get("/ns/rel"), 404)
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, nil)), 201)
}

// v0.73 §E.1 Stored digests, for a database an earlier version wrote: it
// stored the heads' plaintext sizes and sha-256s at every level below
// sealed, at rest included, and nothing later clears them in a namespace
// already at rest. Opening it clears them, once (migration
// 008_clear_at_rest_digests), from the
// revisions of namespaces encrypted at all, and keeps a plain namespace's;
// /heads at rest lists none, even where a row still has them.
func TestV073AtRestDigestsFromBeforeUpgrade(t *testing.T) {
	t.Parallel()
	path, blobs := v073DB(t), t.TempDir()
	ks := newKeyStore(t)
	at := func(o *core.Options) { o.Path, o.BlobDir = path, blobs }
	e := newEnv(t, withKeyStore(ks), withEncTuning, at)
	e.mkNS("r", atRest(map[string]any{"read": "public"}))
	e.mkNS("p", map[string]any{"read": "public"})
	ra := e.create("r", "a", map[string]any{"secret": "guessable"})
	e.appendRev("r", "a", ra, ops(op("add", "/more", 1.0)))
	e.create("p", "b", map[string]any{"b": 1.0})
	e.srv.Close()
	e.e.Close()
	// As an earlier version left it: migration 008_clear_at_rest_digests
	// not applied, and a size and digest on each revision written as a
	// head at rest.
	db, q := v073SQL(t, path)
	stale := func() {
		t.Helper()
		canon := []byte(`{"secret":"guessable"}`)
		sum := sha256.Sum256(canon)
		if _, err := db.Exec(q(`UPDATE revisions SET size = ?, digest = ? WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.name = 'r')`), len(canon), sum[:]); err != nil {
			t.Fatal(err)
		}
	}
	stale()
	v073Unapplied(t, path, "clear_at_rest_digests")
	if n := storedMeta(t, path); n != 3 {
		t.Fatalf("%d revisions with a size or digest before the upgrade, want 3", n)
	}
	e = newEnv(t, withKeyStore(ks), withEncTuning, at)
	if n := storedMeta(t, path); n != 1 {
		t.Fatalf("%d revisions with a size or digest after the upgrade, want the plain head's", n)
	}
	if it := e.headItems("p", e.nsHead("p"))["b"]; it["size"] == nil || it["digest"] == nil {
		t.Fatalf("plain heads %v", it)
	}
	e.srv.Close()
	e.e.Close()
	// Once: a row with them again is left, and /heads at rest still lists
	// none.
	stale()
	e = newEnv(t, withKeyStore(ks), withEncTuning, at)
	if n := storedMeta(t, path); n != 3 {
		t.Fatalf("%d revisions with a size or digest, want 3: the migration ran again", n)
	}
	if it := e.headItems("r", e.nsHead("r"))["a"]; it["created"] == nil || it["size"] != nil || it["digest"] != nil {
		t.Fatalf("at-rest heads %v", it)
	}
}
