package server

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
)

// v0.55 §6.6, §12: a limit refusal names the limit's key, and for sizes and
// counts the measured value and the limit in force. TestValueAndPathSize,
// TestCreatesFromScratch, TestLimits, TestBlobUploadChecks and the batch
// tests check the other paths.

// §6.6: documentSize, nestingDepth and keepPerResource on resources.
func TestV055LimitResourceFields(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("l", map[string]any{"limits": map[string]any{"documentSize": 1000, "patchSetSize": 200,
		"nestingDepth": 3, "keepPerResource": 2}})

	// A document grown past documentSize by appends within patchSetSize.
	doc := map[string]any{"n": 0}
	head := e.create("l", "grow", doc)
	for i := 0; ; i++ {
		k := fmt.Sprintf("k%d", i)
		v := strings.Repeat("x", 90)
		r := e.write("PATCH", "l", "grow", head, ops(op("add", "/"+k, v)))
		doc[k] = v
		if r.Code == 201 {
			head = etagOf(r)
			continue
		}
		expectLimit(t, r, 413, "documentSize", int64(len(canonical(doc))), 1000)
		break
	}

	deep := e.create("l", "deep", map[string]any{"a": map[string]any{"b": map[string]any{}}})
	expectLimit(t, e.write("PATCH", "l", "deep", deep, ops(op("add", "/a/b/c", map[string]any{}))), 422, "nestingDepth", 4, 3)

	r1 := e.create("l", "kept", map[string]any{"v": 1})
	r2 := e.appendRev("l", "kept", r1, ops(op("replace", "/v", 2)))
	r3 := e.appendRev("l", "kept", r2, ops(op("replace", "/v", 3)))
	r4 := e.appendRev("l", "kept", r3, ops(op("replace", "/v", 4)))
	expectLimit(t, e.prune("l", "kept", map[string]any{"horizon": r4, "keep": []any{r1, r2, r3}}, "alice"), 422, "keepPerResource", 3, 2)

	// A batch item's report carries its refusal's fields (§7.5).
	r := e.do(req{method: "POST", path: "/ns/l/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "d2", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"a": map[string]any{"b": map[string]any{"c": map[string]any{}}}})}}}}})
	expectItemLimit(t, r, 422, "nestingDepth", 4, 3)
}

// §6.6: a namespace document over a limit is 422 limit, with sizes for
// sizes and counts, the key alone for durations and rates.
func TestV055LimitConfigFields(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("c", map[string]any{})
	max := core.DefaultMaximums()
	put := func(v any) *resp { return e.patchNS("c", ops(op("add", "/limits", v)), "") }
	expectLimit(t, put(map[string]any{"opsPerSet": 5000}), 422, "opsPerSet", 5000, int64(max.OpsPerSet))
	expectLimit(t, put(map[string]any{"ratePerNamespace": map[string]any{"rate": 1e9, "burst": 1}}), 422, "ratePerNamespace", -1, -1)
	expectLimit(t, put(map[string]any{"retryWindow": "P400D"}), 422, "retryWindow", -1, -1)
	expectLimit(t, put(map[string]any{"remoteRegistration": "P100000D"}), 422, "remoteRegistration", -1, -1)
	expectLimit(t, put(map[string]any{"blobGrace": "PT1M"}), 422, "blobGrace", -1, -1)

	// The document's own rulesPerNamespace bounds its rules.
	rule := map[string]any{"op": "test", "path": "/action", "schema": map[string]any{"type": "string"}}
	expectLimit(t, e.patchNS("c", ops(op("add", "/limits", map[string]any{"rulesPerNamespace": 1}), op("add", "/rules", []any{rule, rule})), ""),
		422, "rulesPerNamespace", 2, 1)
	expect(t, e.patchNS("c", ops(op("add", "/limits", map[string]any{"rulesPerNamespace": 2}), op("add", "/rules", []any{rule, rule})), ""), 201)

	allow := func(k string, v any) *resp {
		return e.patchNS("c", ops(op("add", "/allowances", []any{map[string]any{"sub": "svc:x", "kid": "k", k: v}})), "")
	}
	expectLimit(t, allow("itemsPerBatch", 1e6), 422, "itemsPerBatch", 1e6, int64(max.ItemsPerBatch))
	expectLimit(t, allow("batchSize", 1<<40), 422, "batchSize", 1<<40, int64(max.BatchSize))
	expectLimit(t, allow("blobPending", 1<<40), 422, "blobPending", 1<<40, int64(max.BlobPending))
	expectLimit(t, allow("blobRate", map[string]any{"rate": 1e15, "burst": 1}), 422, "blobRate", -1, -1)

	// Config patch sets and documents (§7.4 step 4).
	e.mkNS("s", map[string]any{"limits": map[string]any{"patchSetSize": 400, "documentSize": 600}})
	big := ops(op("add", "/x-a", strings.Repeat("a", 400)))
	expectLimit(t, e.patchNS("s", big, ""), 413, "patchSetSize", int64(len(canonical(big))), 400)
	expect(t, e.patchNS("s", ops(op("add", "/x-a", strings.Repeat("a", 300))), ""), 201)
	want := map[string]any{"limits": map[string]any{"patchSetSize": 400, "documentSize": 600},
		"x-a": strings.Repeat("a", 300), "x-b": strings.Repeat("b", 300)}
	expectLimit(t, e.patchNS("s", ops(op("add", "/x-b", strings.Repeat("b", 300))), ""), 413, "documentSize", int64(len(canonical(want))), 600)
}

// §6.6: rulesPerGrant is the namespace's, and grantSize the deployment's,
// since a bearer is decoded before any namespace is consulted.
func TestV055LimitGrantFields(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, map[string]any{"limits": map[string]any{"rulesPerGrant": 1}})
	e := f.tenv
	rule := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}
	g := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read", "create"}, map[string]any{"rules": []any{rule, rule}})
	expectLimit(t, e.write("PATCH", "sec", "x", "", addRoot(map[string]any{}), g), 422, "rulesPerGrant", 2, 1)
	g = e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read", "create"}, map[string]any{"rules": []any{rule}})
	expect(t, e.write("PATCH", "sec", "x", "", addRoot(map[string]any{}), g), 201)

	gs := int64(core.DefaultMaximums().GrantSize)
	// Too long to decode: measured is a lower bound, the decoded length.
	expectLimit(t, e.write("PATCH", "sec", "y", "", addRoot(map[string]any{}), strings.Repeat("A", 12000)), 413, "grantSize", 9000, gs)
	// Decoded, one byte over.
	n := base64.URLEncoding.EncodedLen(int(gs))
	expectLimit(t, e.write("PATCH", "sec", "y", "", addRoot(map[string]any{}), strings.Repeat("A", n)), 413, "grantSize", gs+1, gs)

	// Edge-grant exchanges (§C.5.2): a grant too large, and a body too
	// large to hold the grants it may, counted in the body's bytes read.
	reader := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"})
	expectLimit(t, e.issueGrants(reader, strings.Repeat("A", 12000)), 413, "grantSize", 9000, gs)
	bound := core.MaxEdgeGrants*(len("biscuit:")+base64.URLEncoding.EncodedLen(int(gs))+4) + 4096
	r := e.do(req{method: "POST", path: "/edge-grants", raw: `{"grants": ["` + strings.Repeat("A", 600<<10) + `"]}`})
	expectLimit(t, r, 413, "grantSize", int64(bound+1), gs)
}

// §6.6: branchesPerNamespace, on creation and unfreezing, and branchDepth.
func TestV055LimitBranchFields(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(o *core.Options) {
		l := core.DefaultLimits()
		l.BranchDepth = 2
		o.Limits, o.Maximums = l, l
	})
	e.mkNS("m", map[string]any{"limits": map[string]any{"branchesPerNamespace": 1}})
	at := e.nsHead("m")
	expect(t, e.branch("m", map[string]any{"name": "m1", "at": at}, "alice"), 201)
	expectLimit(t, e.branch("m", map[string]any{"name": "m2", "at": at}, "alice"), 422, "branchesPerNamespace", 2, 1)
	expect(t, e.patchNS("m1", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.branch("m", map[string]any{"name": "m2", "at": at}, "alice"), 201)
	expectLimit(t, e.patchNS("m1", ops(op("replace", "/frozen", false)), ""), 422, "branchesPerNamespace", 2, 1)

	expect(t, e.branch("m2", map[string]any{"name": "m3", "at": e.nsHead("m2")}, "alice"), 201)
	expectLimit(t, e.branch("m3", map[string]any{"name": "m4", "at": e.nsHead("m3")}, "alice"), 422, "branchDepth", 3, 2)
}

// §6.6: a body the server stops reading before step 1 of §6.2 names the
// deployment's limit, with the bytes read as a lower bound; a batch's
// names the principal's batchSize (§7.5). A body no limit of §6.6 covers
// is 400.
func TestV055LimitOversizedBodies(t *testing.T) {
	t.Parallel()
	l := core.DefaultLimits()
	l.DocumentSize, l.PatchSetSize, l.BatchSize, l.ItemsPerBatch = 64<<10, 16<<10, 2048, 10
	e := newEnv(t, func(o *core.Options) { o.Limits, o.Maximums = l, l })
	e.mkNS("b", map[string]any{})
	at := e.nsHead("b")
	bound := 4 * (64 << 10)
	pad := strings.Repeat("x", 300<<10)
	expectLimit(t, e.write("PATCH", "b", "r", "", addRoot(map[string]any{"a": pad})), 413, "documentSize", int64(bound+1), 64<<10)
	expectLimit(t, e.patchNS("b", ops(op("add", "/x-a", pad)), ""), 413, "patchSetSize", int64(bound+1), 16<<10)
	expectLimit(t, e.branch("b", map[string]any{"name": "b1", "at": at, "x-pad": pad}, "alice"), 413, "patchSetSize", int64(bound+1), 16<<10)
	batchBound := 2048 + 2048/4 + 512*10 + (64 << 10) + 64<<10
	r := e.do(req{method: "POST", path: "/ns/b/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "r", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"a": pad})}}}}})
	expectLimit(t, r, 413, "batchSize", int64(batchBound+1), 2048)

	h := e.create("b", "p", map[string]any{})
	expectCode(t, e.prune("b", "p", map[string]any{"horizon": h, "x-pad": strings.Repeat("x", 1<<20)}, "alice"), 400, "bad_input")
}

// §6.6: a blob body sent without Content-Length is read up to blobSize, so
// measured is a lower bound.
func TestV055LimitStreamedBlob(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("c", map[string]any{"limits": map[string]any{"blobSize": 1000}})
	data := []byte(strings.Repeat("b", 5000))
	pr, pw := io.Pipe()
	go func() { pw.Write(data); pw.Close() }()
	hr, err := http.NewRequest("PUT", e.srv.URL+"/r/c/a/blob/"+blobID("text/plain", "", data), pr)
	if err != nil {
		t.Fatal(err)
	}
	hr.ContentLength = -1
	hr.Header.Set("Content-Type", "text/plain")
	hr.Header.Set("X-Author", "alice")
	res, err := client.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	expectLimit(t, &resp{Code: res.StatusCode, H: res.Header, Body: b}, 413, "blobSize", 1001, 1000)
}
