package merge_test

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.73 §F.3 kept bullet, §E.3.1, Addendum E Levels (MF-5, P35): an E3
// base raised from sealed whose head of a resource is from before the
// raise and references a blob uploaded at E2, which a sealed op can't
// declare, makes no item for that resource when the merge keeps the base:
// the rest of the batch commits, and the resource is offered again. The
// base's document from before the raise is served sealed as at E2 and
// folded by the merge's view with the key of its epoch.
func TestV073P35KeptPreRaiseBlobMakesNoItem(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	noErr(t, err)
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("alice"))
	_, priv, err := seal.GenerateRecipient()
	noErr(t, err)
	x := c.E2E(priv)
	must(c.CreateNamespace(ctx, "m", map[string]any{"encryption": map[string]any{"level": "sealed"}, "merge": devAuthors}))
	data := []byte("a picture uploaded at E2")
	nonce := seal.NewNonce()
	bid := must(c.UploadBlob(ctx, "m", "derby", "image/png", nonce, data))
	b := must(c.Create(ctx, "m", "derby", ops(op("add", "", map[string]any{"title": "Derby", "img": client.BlobRef(bid, "image/png", len(data), nonce)}), op("add", "/$nonce", seal.NewNonce())))).ID
	must(c.Create(ctx, "m", "cup", ops(op("add", "", map[string]any{"title": "Cup", "score": "0-0"}), op("add", "/$nonce", seal.NewNonce()))))
	// The keys of the epoch before the raise, as /keys gives them at E2.
	for _, k := range must(c.FetchKeys(ctx, "m", nil, nil)) {
		x.AddKey(k.Kid, k.Key)
	}
	h := must(c.NSHead(ctx, "m"))
	must(c.PatchConfig(ctx, "m", h.Config, ops(op("add", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0}))))
	must(x.InitKeyring(ctx, "m"))

	must(c.CreateBranch(ctx, "m", client.BranchRequest{Name: "r7"}))
	must(x.InitKeyring(ctx, "r7"))
	// The branch drops the E2 blob, which an e2e write can't declare.
	must(x.AppendSealed(ctx, "r7", "derby", b, ops(rm("/img"), op("add", "/score", "1-0"))))
	cupHead := must(c.Head(ctx, "r7", "cup")).ID
	must(x.AppendSealed(ctx, "r7", "cup", cupHead, ops(op("replace", "/score", "2-0"))))

	p := must(merge.NewPlan(ctx, c, "m", "r7", merge.Options{E2E: x}))
	wantClasses(t, p, map[string]merge.Class{"derby": merge.FastForward, "cup": merge.FastForward})
	noErr(t, p.Resolve("derby")) // keep the base
	r := p.Resource("derby")
	if r.Kept || r.HasItem() || !strings.Contains(r.Note, "image/png") || !strings.Contains(r.Note, "offered again") {
		t.Fatalf("kept over an E2 blob: %+v", r)
	}
	if !p.Clean() || len(p.Items()) != 1 {
		t.Fatalf("plan %+v", p.Items())
	}
	res := must(p.Apply(ctx))
	if len(res.Items) != 1 || res.Items[0].Resource != "cup" {
		t.Fatalf("batch %+v", res.Items)
	}
	if got := must(c.Head(ctx, "m", "derby")).ID; got != b {
		t.Fatalf("derby moved to %s", got)
	}
	_, d := must2(x.LoadE2E(ctx, "m", "cup"))
	if d.Value.(map[string]any)["score"] != "2-0" {
		t.Fatalf("cup %v", d.Value)
	}
	// The next plan offers derby again.
	p = must(merge.NewPlan(ctx, c, "m", "r7", merge.Options{E2E: x}))
	if r := p.Resource("derby"); r == nil || r.Class != merge.FastForward && r.Class != merge.Replay {
		t.Fatalf("derby not offered again: %+v", r)
	}
}
