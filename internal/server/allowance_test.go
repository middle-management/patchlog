package server

import (
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
)

// batchOf builds a batch body creating n resources named prefix-0….
func batchOf(prefix string, n int) map[string]any {
	items := make([]any, n)
	for i := range items {
		items[i] = map[string]any{"resource": fmt.Sprintf("%s-%d", prefix, i), "ifNoneMatch": "*",
			"steps": []any{addRoot(map[string]any{"i": i})}}
	}
	return map[string]any{"items": items}
}

// §6.6 allowances: a named principal gets its own rate and batch limits.
func TestAllowances(t *testing.T) {
	max := core.DefaultLimits()
	max.ItemsPerBatch = 50
	f := newAuthFixture(t, map[string]any{
		"limits": map[string]any{
			"itemsPerBatch":    2,
			"ratePerPrincipal": map[string]any{"rate": 1, "burst": 3},
		},
		"allowances": []any{map[string]any{
			"sub": "user:bob", "kid": "issuer", "rate": 100, "burst": 1000,
			"itemsPerBatch": 20, "batchSize": "1 MiB"}},
	}, func(o *core.Options) { o.Maximums = max })
	e := f.tenv
	eve := e.grant(f.issuer, "user:eve", []string{"sec"}, []string{"read", "create", "append"})
	batch := func(bearer string, body any) *resp {
		return e.do(req{method: "POST", path: "/ns/sec/batch", body: body, bearer: bearer})
	}

	// Without an allowance the namespace's limits apply…
	expectCode(t, batch(eve, batchOf("e", 3)), 413, "limit")
	// …with one, the allowance's.
	expect(t, batch(f.issuerG, batchOf("b", 20)), 201)
	expectCode(t, batch(f.issuerG, batchOf("c", 21)), 413, "limit")

	// Bob's 20 items drew on the allowance's bucket, not the namespace's
	// or a principal's, so eve still has her own tokens.
	expect(t, batch(eve, batchOf("e", 2)), 201) // 3 → 1 token
	expect(t, batch(eve, batchOf("f", 2)), 201) // admitted with 1 left, → -1
	expectCode(t, batch(eve, batchOf("g", 2)), 429, "rate")
	expect(t, batch(f.issuerG, batchOf("d", 20)), 201)

	// Allowances are guarded by a * key and bounded by the deployment maximums.
	cid := e.configID("sec", f.adminG)
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: cid, bearer: f.issuerG,
		body: ops(op("replace", "/allowances/0/rate", 1000))}), 403, "forbidden")
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: cid, bearer: f.adminG,
		body: ops(op("replace", "/allowances/0/itemsPerBatch", 51))}), 422, "limit")
	expectCode(t, e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: cid, bearer: f.adminG,
		body: ops(op("replace", "/allowances/0/batchSize", "lots"))}), 422, "invalid")
	expect(t, e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: cid, bearer: f.adminG,
		body: ops(op("replace", "/allowances/0/itemsPerBatch", 50))}), 201)

	// A namespace may also write size limits with units.
	cid = e.configID("sec", f.adminG)
	expect(t, e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: cid, bearer: f.adminG,
		body: ops(op("add", "/limits/batchSize", "2 KiB"))}), 201)
}
