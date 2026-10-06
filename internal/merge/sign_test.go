package merge_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/sig"
)

func testKey(t *testing.T) (sig.Key, sig.Signer) {
	t.Helper()
	k, err := sig.ParseKey("bot-1:" + "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err != nil {
		t.Fatal(err)
	}
	ss, err := sig.ParseSigners([]any{k.Entry()})
	if err != nil {
		t.Fatal(err)
	}
	return k, ss[0]
}

// checkStep verifies a step's signature against the digest the spec gives
// for ns/name on parent, and returns the id the step produces.
func checkStep(t *testing.T, signer sig.Signer, origin, ns, name string, parent string, s client.Step) string {
	t.Helper()
	if s.Signature == "" {
		t.Fatalf("%s/%s: step without a signature", ns, name)
	}
	parsed, err := sig.Parse(s.Signature)
	if err != nil {
		t.Fatal(err)
	}
	var par *ids.ID
	if parent != "" {
		id := must(ids.Parse(parent))
		par = &id
	}
	var body []byte
	if !s.Delete {
		body = jsonv.Canonical(must(client.ToValue(s.Patches)))
	}
	if !sig.Verify(signer, parsed, sig.Digest(origin, ns, name, par, body)) {
		t.Fatalf("%s/%s on %q: signature does not verify", ns, name, parent)
	}
	if s.Delete {
		return ids.Tombstone(*par).String()
	}
	return ids.Revision(par, body).String()
}

func TestSignedStepsFastForwardAndReplay(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "derby", op("replace", "/score", "2-0"))
	e.del("r7", "cup")
	e.create("r7", "final", map[string]any{"title": "Final"})
	key, signer := testKey(t)

	// Unsigned by default: no step carries a signature, in particular none
	// of a source revision (§C.3).
	plain := e.plan("matches", "r7", merge.Options{})
	for _, it := range plain.Batch().Items {
		for _, s := range it.Steps {
			if s.Signature != "" {
				t.Fatalf("%s: unsigned plan has signature %q", it.Resource, s.Signature)
			}
		}
	}

	p := e.plan("matches", "r7", merge.Options{Signer: &key})
	req := p.Batch()
	if len(req.Items) != 3 {
		t.Fatalf("items %+v", req.Items)
	}
	for _, it := range req.Items {
		parent := it.IfMatch
		for _, s := range it.Steps {
			parent = checkStep(t, signer, clienttest.Origin, "matches", it.Resource, parent, s)
		}
	}
	// The plan's own steps stay unsigned: signing happens on the request.
	if p.Resource("derby").Steps[0].Signature != "" {
		t.Fatal("plan steps were mutated")
	}
	// The signature travels as the step object's member.
	body := merge.BatchBody(req)
	step0 := body["items"].([]any)[0].(map[string]any)["steps"].([]any)[0].(map[string]any)
	if step0["signature"] == "" || step0["signature"] == nil {
		t.Fatalf("body step %v has no signature", step0)
	}
}

func TestSignedReplayAfterTargetMoved(t *testing.T) {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("matches", "derby", op("replace", "/title", "Derby day"))
	key, signer := testKey(t)

	p := e.plan("matches", "r7", merge.Options{Signer: &key})
	wantClasses(t, p, map[string]merge.Class{"derby": merge.Replay})
	it := p.Batch().Items[0]
	if it.IfMatch != e.head("matches", "derby").ID {
		t.Fatalf("ifMatch %s", it.IfMatch)
	}
	checkStep(t, signer, clienttest.Origin, "matches", "derby", it.IfMatch, it.Steps[0])
}

func TestSignStepsChainsParentsAndTombstones(t *testing.T) {
	key, signer := testKey(t)
	parent := ids.Hash(nil, []byte("x")).String()
	patches := ops(op("replace", "/a", 1))
	in := []client.Step{
		client.PatchStep(patches).WithGesture("g1", ""),
		client.DeleteStep(),
		client.PatchStep(ops(op("replace", "/a", 2))),
	}
	in[0].Signature = "Ed25519:bot-1:copied-from-source"
	out, err := merge.SignSteps(key, "https://t.example", "ns", "r", parent, in)
	if err != nil {
		t.Fatal(err)
	}
	prev := parent
	for _, s := range out {
		prev = checkStep(t, signer, "https://t.example", "ns", "r", prev, s)
	}
	if out[0].Gesture != "g1" || out[0].Signature == in[0].Signature {
		t.Fatalf("first step %+v", out[0])
	}
	// Genesis: no parent.
	g, err := merge.SignSteps(key, "https://t.example", "ns", "r", "", []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"a": 1}))})
	if err != nil {
		t.Fatal(err)
	}
	checkStep(t, signer, "https://t.example", "ns", "r", "", g[0])
	// A pruned step can't be signed.
	if _, err := merge.SignSteps(key, "https://t.example", "ns", "r", parent, []client.Step{{}}); err == nil {
		t.Fatal("pruned step signed")
	}
}
