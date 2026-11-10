package bundle_test

import (
	"bytes"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// KEYS-4 (§E.2.2, TOOLS §G.4.2): a sealed namespace's grants are sealed
// under K_n since v0.81; the exporter derives it from the K_e /keys gives
// and the bundle carries the grant line, so the signatures verify.
func TestV081ExportOpensGrantUnderKn(t *testing.T) {
	t.Parallel()
	nsKey := clienttest.NewKey("ns-key")
	bot := signerKey(t, "bot-1", 1)
	g := mintFor(t, nsKey.Priv, nsKey.Kid, "alice", "s", bot)
	served := map[string]*grant.Grant{g.ID().String(): g}
	src := newWrappedEncDeployment(t, stagingOrigin, sealedGrantsHandler(t, served, func(a string) *grant.Grant {
		if a == "alice" {
			return g
		}
		return nil
	}, []map[string]any{}))
	src.ns("s", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"},
		"keys": []any{nsKey.Entry("create", "append", "delete", "read")}})
	canon := func(p any) []byte { return jsonv.Canonical(must(client.ToValue(p))) }
	p1 := append(client.GenesisPatches(map[string]any{"v": marker}), op("add", "/$nonce", seal.NewNonce()))
	r1 := must(src.c.Create(ctx, "s", "a", p1, client.WithSignature(bot.SignPatches(stagingOrigin, "s", "a", nil, canon(p1))))).ID
	par := must(ids.Parse(r1))
	p2 := nonce(op("add", "/w", 2.0))
	must(src.c.Append(ctx, "s", "a", r1, p2, client.WithSignature(bot.SignPatches(stagingOrigin, "s", "a", &par, canon(p2)))))
	var buf bytes.Buffer
	plan, _, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"s"}, Authors: true, Plaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Notes) != 0 {
		t.Fatalf("notes %v", plan.Notes)
	}
	n := 0
	for _, m := range lineMaps(t, buf.Bytes())[1:] {
		if m["stored"] != nil {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d grant lines", n)
	}
}
