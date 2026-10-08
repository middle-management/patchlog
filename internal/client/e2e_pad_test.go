package client_test

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
)

// patchSetPadded opens the sealed patch set of revision id of ns/name and
// reports whether it is padded to its bucket (§E.3.1).
func patchSetPadded(t *testing.T, c *client.Client, x *client.E2E, ns, name, id string) bool {
	t.Helper()
	ctx := context.Background()
	for _, le := range must(c.Log(ctx, ns, name, id, "")) {
		if le.ID != id {
			continue
		}
		jwe, ok := seal.SealedJWE(le.Patches)
		if !ok {
			t.Fatalf("%s is not sealed", id)
		}
		h := must(seal.ParseHeader(jwe))
		kns, _, _ := seal.ParseKid(h.Kid)
		_, padded, err := seal.OpenPatchSetPadded(le.Patches, must(x.Key(ctx, h.Kid)), h.Kid, kns, name, le.Parent)
		if err != nil {
			t.Fatal(err)
		}
		return padded
	}
	t.Fatalf("%s not in the log", id)
	return false
}

// In an e2e namespace with pad, clients pad every sealed patch set; a fold
// flags one that isn't padded, but not what was sealed before pad was
// turned on. A merge into it pads what it re-encrypts (§E.2.2, §E.3.1).
func TestE2EPadding(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t)})
	c := s.Client(t, client.WithAuthor("alice"))
	_, priv, _ := seal.GenerateRecipient()
	x := c.E2E(priv)
	must(c.CreateNamespace(ctx, "e", map[string]any{"encryption": map[string]any{"level": "e2e"},
		"merge": map[string]any{"authors": []any{map[string]any{"sub": "alice", "kid": "dev"}}}}))
	must(x.InitKeyring(ctx, "e"))

	// Before pad: not padded, and never flagged.
	old := must(x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 0}))
	if patchSetPadded(t, c, x, "e", "d", old.ID) {
		t.Fatal("padded without pad")
	}
	h := must(c.NSHead(ctx, "e"))
	must(c.PatchConfig(ctx, "e", h.Config, []any{op("add", "/encryption/pad", true)}))
	sameJSON(t, must(x.DocE2E(ctx, "e", "d", old.ID)).Value, map[string]any{"n": 0})

	p1 := must(x.AppendSealed(ctx, "e", "d", old.ID, ops(op("replace", "/n", 1))))
	if !patchSetPadded(t, c, x, "e", "d", p1.ID) {
		t.Fatal("not padded with pad")
	}
	// An unpadded patch set written behind the client's back is flagged.
	body := must(seal.SealPatchSet(must(x.Key(ctx, "e#1")), "e#1", "e", "d", p1.ID, ops(op("replace", "/n", 2))))
	bad := must(c.Append(ctx, "e", "d", p1.ID, body))
	d := must(x.DocE2E(ctx, "e", "d", bad.ID))
	if len(d.Flagged) != 1 || d.Flagged[0].ID != bad.ID || !strings.Contains(d.Flagged[0].Message, "padded") || d.ValidID != p1.ID {
		t.Fatalf("fold %+v", d)
	}
	sameJSON(t, d.Value, map[string]any{"n": 1})

	// A branch copies pad; its merge back is re-encrypted and padded.
	must(c.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"}))
	must(x.InitKeyring(ctx, "eb"))
	must(x.CreateDocSealed(ctx, "eb", "f", map[string]any{"title": strings.Repeat("x", 3000)}))
	p := must(merge.NewPlan(ctx, c, "e", "eb", merge.Options{E2E: x}))
	must(p.Apply(ctx))
	fh := must(c.Head(ctx, "e", "f"))
	if !patchSetPadded(t, c, x, "e", "f", fh.ID) {
		t.Fatal("merged patch set not padded")
	}
	_, fd := must2(x.LoadE2E(ctx, "e", "f"))
	if len(fd.Flagged) > 0 {
		t.Fatalf("flagged %+v", fd.Flagged)
	}
}
