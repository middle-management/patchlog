package merge_test

import (
	"crypto/ecdh"
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.73 §E.3.2 (ENC-25): a revision a fold flags only for its padding is
// still folded, so OpenLog gives a merge its patches and the merge carries
// it, re-sealed and padded for the target, rather than calling it
// unreadable.
func TestV073P29MergeCarriesUnpaddedRevision(t *testing.T) {
	t.Parallel()
	e := newE3(t, map[string]any{"encryption": map[string]any{"level": "e2e", "pad": true}, "merge": devAuthors})
	e.branch("b")
	h := must(e.c.Head(ctx, "b", "derby"))
	kr := must(seal.ResourceKey(must(e.x.Key(ctx, "b#1")), "b", "derby"))
	unpadded := must(seal.SealPatchSet(kr, "b#1", "b", "derby", h.ID, jsonv.FromGo(ops(map[string]any{"op": "replace", "path": "/score", "value": "2-0"}))))
	must(e.c.Append(ctx, "b", "derby", h.ID, unpadded))
	_, d := must2(e.x.LoadE2E(ctx, "b", "derby"))
	if len(d.Flagged) != 1 {
		t.Fatalf("the unpadded revision isn't flagged: %+v", d)
	}
	p := e.plan("m", "b")
	r := p.Resource("derby")
	if r == nil || len(r.Conflicts) != 0 || !r.HasItem() {
		t.Fatalf("derby in the plan: %+v", r)
	}
	must(p.Apply(ctx))
	if got := e.doc("m", "derby").(map[string]any)["score"]; got != "2-0" {
		t.Fatalf("merged score %v", got)
	}
}

// Wave-2 carry-over (§F.9, §F.8.1): a release rebase passes
// SuccessorReaders to each branch's rebase, so an e2e release branch
// whose reader the view doesn't know is rebased with that reader kept,
// rather than stopping with ErrReadersDropped.
func TestV073P29RebaseReleaseSuccessorReaders(t *testing.T) {
	t.Parallel()
	e := newE3(t, map[string]any{"encryption": map[string]any{"level": "e2e"}})
	_, reader, err := seal.GenerateRecipient()
	noErr(t, err)
	must(e.c.CreateBranch(ctx, "m", client.BranchRequest{Name: "r7"}))
	must(e.x.InitKeyring(ctx, "r7", reader.PublicKey()))
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	must(e.c.CreateNamespace(ctx, "releases", map[string]any{}))
	nd := must(e.c.NSDoc(ctx, "r7", must(e.c.NSHead(ctx, "r7")).ID))
	at, _ := nd.Value["base"].(map[string]any)["at"].(string)
	must(release.Write(ctx, e.c, release.Ref{NS: "releases", Name: "rel"}, "", &release.Doc{Name: "rel", Branches: map[string]release.Branch{"m": {NS: "r7", At: at}}}))
	opt := merge.RebaseReleaseOptions{Release: "/r/releases/rel", Suffix: "-b", Plan: merge.Options{E2E: e.x}}
	if _, err := merge.RebaseRelease(ctx, e.c, opt); !errors.Is(err, merge.ErrReadersDropped) {
		t.Fatalf("without the reader: %v, want ErrReadersDropped", err)
	}
	opt.SuccessorReaders = []*ecdh.PublicKey{reader.PublicKey()}
	res := must(merge.RebaseRelease(ctx, e.c, opt))
	if res.Revision == "" || res.Rebases["m"] == nil || !res.Rebases["m"].Switched {
		t.Fatalf("release rebase %+v", res)
	}
	kr, _ := must2(e.x.Keyring(ctx, "r7-b"))
	if _, ok := kr.Entry(seal.Kid("r7-b", kr.Current("r7-b")), seal.Thumbprint(reader.PublicKey())); !ok {
		t.Fatal("the successor's keyring holds no key for the reader")
	}
}

// Wave-2 carry-over (§7.5): a dry run reports a failing item in its 200,
// fast-forward or not; DryRun returns it as the *client.APIError with code
// "batch" it documents, so `patchlog merge plan` no longer prints "dry run
// ok" for a replay whose target moved after planning.
func TestV073P29DryRunReportsFailingReplay(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("matches", "derby", op("replace", "/title", "The Derby"))
	p := e.plan("matches", "r7", merge.Options{})
	if r := p.Resource("derby"); r == nil || r.Expected != nil || !r.HasItem() {
		t.Fatalf("derby should be a replay, not a fast-forward: %+v", r)
	}
	e.append("matches", "derby", op("replace", "/title", "Derby day"))
	dry, err := p.DryRun(ctx)
	ae, ok := client.AsAPIError(err)
	if !ok || ae.Code != "batch" || ae.Status != 412 || len(ae.Items()) != 1 || dry == nil {
		t.Fatalf("dry run after the target moved: %v (report %+v)", err, dry)
	}
	if ae.Items()[0]["resource"] != "derby" {
		t.Fatalf("failing items %v", ae.Items())
	}
}
