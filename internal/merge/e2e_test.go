package merge_test

import (
	"crypto/ecdh"
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
)

// e3env is an e2e base "m" with its own keyring and a key holder x. With
// authentication off, x reads keys from the keyrings directly and
// merge.authors matches alice on sub alone.
type e3env struct {
	t    *testing.T
	c    *client.Client
	x    *client.E2E
	priv *ecdh.PrivateKey
}

func newE3(t *testing.T, doc map[string]any) *e3env {
	ks, err := keystore.New(keystore.Generate())
	noErr(t, err)
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("alice"))
	_, priv, err := seal.GenerateRecipient()
	noErr(t, err)
	e := &e3env{t: t, c: c, x: c.E2E(priv), priv: priv}
	if doc == nil {
		doc = map[string]any{"encryption": map[string]any{"level": "e2e"}, "merge": devAuthors}
	}
	must(c.CreateNamespace(ctx, "m", doc))
	must(e.x.InitKeyring(ctx, "m"))
	must(e.x.CreateDocSealed(ctx, "m", "derby", map[string]any{"title": "Derby", "score": "0-0"}))
	must(e.x.CreateDocSealed(ctx, "m", "cup", map[string]any{"title": "Cup", "score": "1-1"}))
	return e
}

func (e *e3env) branch(name string) {
	e.t.Helper()
	must(e.c.CreateBranch(ctx, "m", client.BranchRequest{Name: name}))
	must(e.x.InitKeyring(ctx, name))
}

func (e *e3env) append(ns, name string, patches ...map[string]any) string {
	e.t.Helper()
	h := must(e.c.Head(ctx, ns, name))
	return must(e.x.AppendSealed(ctx, ns, name, h.ID, ops(patches...))).ID
}

func (e *e3env) doc(ns, name string) any {
	e.t.Helper()
	_, d := must2(e.x.LoadE2E(ctx, ns, name))
	if d == nil {
		return nil
	}
	if len(d.Flagged) > 0 {
		e.t.Fatalf("%s/%s: flagged %+v", ns, name, d.Flagged)
	}
	return d.Value
}

func (e *e3env) plan(target, branch string) *merge.Plan {
	e.t.Helper()
	return must(merge.NewPlan(ctx, e.c, target, branch, merge.Options{E2E: e.x}))
}

// kids returns the kid of every sealed patch set in ns/name's log.
func (e *e3env) kids(ns, name string) []string {
	e.t.Helper()
	h := must(e.c.Head(ctx, ns, name))
	var out []string
	for _, le := range must(e.c.Log(ctx, ns, name, h.ID, "")) {
		if jwe, ok := seal.SealedJWE(le.Patches); ok {
			out = append(out, must(seal.ParseHeader(jwe)).Kid)
		}
	}
	return out
}

func sameDoc(t *testing.T, got, want any) {
	t.Helper()
	if !jsonv.Equal(jsonv.FromGo(got), jsonv.FromGo(want)) {
		t.Fatalf("got %s, want %s", jsonv.Canonical(jsonv.FromGo(got)), jsonv.Canonical(jsonv.FromGo(want)))
	}
}

// Merging an e2e branch decrypts and re-encrypts under the base's keys:
// what would fast-forward gets new ids, the branch's keyring isn't merged,
// a second merge finds everything merged through the merge batch, and the
// base then needs none of the branch's keys (§F.8).
func TestE2EMergeReencrypts(t *testing.T) {
	e := newE3(t, nil)
	if _, err := merge.NewPlan(ctx, e.c, "m", "m", merge.Options{}); err == nil || !strings.Contains(err.Error(), "e2e") {
		t.Fatalf("no keys: %v", err)
	}
	e.branch("r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "derby", op("replace", "/score", "2-0"))
	must(e.c.Delete(ctx, "r7", "cup", must(e.c.Head(ctx, "r7", "cup")).ID))
	must(e.x.CreateDocSealed(ctx, "r7", "final", map[string]any{"title": "Final"}))

	p := e.plan("m", "r7")
	if !p.Reencrypt || p.TargetLevel != "e2e" || p.BranchLevel != "e2e" {
		t.Fatalf("plan levels %+v", p)
	}
	wantClasses(t, p, map[string]merge.Class{"derby": merge.FastForward, "cup": merge.FastForward, "final": merge.FastForward})
	for _, r := range p.Resources {
		if r.Expected != nil || r.Status() != "ahead" {
			t.Fatalf("%s: %+v", r.Name, r)
		}
	}
	if !p.Clean() {
		t.Fatalf("not clean: %+v", p.Conflicting())
	}
	dry := must(p.DryRun(ctx))
	res := must(p.Apply(ctx))
	for i, it := range res.Items {
		if strings.Join(it.IDs, ",") != strings.Join(dry.Items[i].IDs, ",") {
			t.Fatalf("%s: dry run %v, apply %v: the same sealed bytes must give the same ids", it.Resource, dry.Items[i].IDs, it.IDs)
		}
	}
	for _, n := range []string{"derby", "final"} {
		if must(e.c.Head(ctx, "m", n)).ID == must(e.c.Head(ctx, "r7", n)).ID {
			t.Fatalf("%s fast-forwarded", n)
		}
		sameDoc(t, e.doc("m", n), e.doc("r7", n))
	}
	if h := must(e.c.Head(ctx, "m", "cup")); h.State != client.Tombstoned {
		t.Fatalf("cup %+v", h)
	}
	for _, k := range append(e.kids("m", "derby"), e.kids("m", "final")...) {
		if k != "m#1" {
			t.Fatalf("base holds a patch set sealed under %s", k)
		}
	}
	kr, _ := must2(e.x.Keyring(ctx, "m"))
	if kr.NS != "m" {
		t.Fatalf("keyring merged: %+v", kr)
	}

	// Again: merged through the merge batch's pairs.
	p2 := e.plan("m", "r7")
	wantClasses(t, p2, map[string]merge.Class{"derby": merge.Merged, "cup": merge.Merged, "final": merge.Merged})
	if r := must(p2.Apply(ctx)); !r.Noop {
		t.Fatalf("second apply %+v", r)
	}
	// A later change in the branch replays alone.
	e.append("r7", "derby", op("add", "/extra", true))
	p3 := e.plan("m", "r7")
	if d := p3.Resource("derby"); d.Class != merge.Replay || d.Pair == nil || !d.Pair.Used || len(d.Steps) != 1 || d.NeedsPerson() {
		t.Fatalf("derby %+v", d)
	}
	must(p3.Apply(ctx))
	sameDoc(t, e.doc("m", "derby"), map[string]any{"title": "Derby", "score": "2-0", "extra": true})

	// Purge the frozen branch: the base folds with its own keys alone.
	must(merge.Freeze(ctx, e.c, "r7", res.NSID))
	must(e.c.PurgeNamespace(ctx, "r7", must(e.c.NSHead(ctx, "r7")).ID))
	only := e.c.E2EKeys(map[string][]byte{"m#1": must(e.x.Key(ctx, "m#1"))})
	for _, n := range []string{"derby", "final"} {
		_, d := must2(only.LoadE2E(ctx, "m", n))
		if len(d.Flagged) > 0 {
			t.Fatalf("%s flagged %+v", n, d.Flagged)
		}
	}
}

// Replays and conflicts work on the plaintext exactly as in a plaintext
// namespace; resolutions are sealed too.
func TestE2EReplayAndConflicts(t *testing.T) {
	e := newE3(t, nil)
	must(e.x.CreateDocSealed(ctx, "m", "pen", map[string]any{"n": 0}))
	e.branch("r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("m", "derby", op("replace", "/title", "Derby!"))
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	e.append("m", "cup", op("replace", "/score", "1-2"))
	e.append("r7", "pen", op("replace", "/n", 1))
	e.append("m", "pen", op("replace", "/n", 2))

	p := e.plan("m", "r7")
	wantClasses(t, p, map[string]merge.Class{"derby": merge.Replay, "cup": merge.Replay, "pen": merge.Replay})
	// Kept at the base: recorded with a sealed empty set (§F.3).
	noErr(t, p.Resolve("pen"))
	penBefore := must(e.c.Head(ctx, "m", "pen")).ID
	if d := p.Resource("derby"); d.NeedsPerson() || strings.Join(d.BranchWrites, ",") != "/score" || strings.Join(d.BaseWrites, ",") != "/title" {
		t.Fatalf("derby %+v", d)
	}
	c := p.Resource("cup")
	if !hasConflict(c, merge.ConflictOverlap) {
		t.Fatalf("cup %+v", c)
	}
	if _, err := p.Apply(ctx); !errors.Is(err, merge.ErrConflicts) {
		t.Fatalf("apply with conflicts: %v", err)
	}
	noErr(t, p.Resolve("cup", client.PatchStep(ops(op("replace", "/score", "2-2")))))
	must(p.Apply(ctx))
	sameDoc(t, e.doc("m", "derby"), map[string]any{"title": "Derby!", "score": "1-0"})
	sameDoc(t, e.doc("m", "cup"), map[string]any{"title": "Cup", "score": "2-2"})
	if h := must(e.c.Head(ctx, "m", "pen")); h.ID == penBefore || len(e.kids("m", "pen")) != 3 {
		t.Fatalf("pen not recorded with a sealed set: %+v %v", h, e.kids("m", "pen"))
	}
	sameDoc(t, e.doc("m", "pen"), map[string]any{"n": 2})
	if d := e.plan("m", "r7").Resource("pen"); d.Class != merge.Merged {
		t.Fatalf("pen after the merge %+v", d)
	}
}

// Without merge.authors there are no merge points: a resource the base
// already holds with the branch's document counts as merged by content,
// one the branch changed since conflicts (rebase first).
func TestE2EMergeWithoutAuthors(t *testing.T) {
	e := newE3(t, map[string]any{"encryption": map[string]any{"level": "e2e"}})
	e.branch("r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	must(e.plan("m", "r7").Apply(ctx))
	p := e.plan("m", "r7")
	if d := p.Resource("derby"); d.Class != merge.Merged || !strings.Contains(d.Note, "already has") {
		t.Fatalf("derby %+v", d)
	}
	e.append("r7", "derby", op("replace", "/score", "2-0"))
	if d := e.plan("m", "r7").Resource("derby"); !hasConflict(d, merge.ConflictOverlap) {
		t.Fatalf("derby after a new change %+v", d)
	}
}

// The merger validates what it re-encrypts (§E.3.2): a branch revision
// that doesn't validate against its $schema makes the resource an invalid
// conflict, and a resolution that fixes it goes through.
func TestE2EMergeValidates(t *testing.T) {
	e := newE3(t, nil)
	must(e.c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}))
	sch := must(e.c.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object", "properties": map[string]any{"n": map[string]any{"type": "number"}}}))
	ref := "/r/schemas/item/rev/" + sch.ID
	must(e.x.CreateDocSealed(ctx, "m", "item", map[string]any{"$schema": ref, "n": 1}))
	e.branch("r7")
	h := must(e.c.Head(ctx, "r7", "item"))
	must(e.x.WithoutValidation().AppendSealed(ctx, "r7", "item", h.ID, ops(op("replace", "/n", "one"))))

	p := e.plan("m", "r7")
	it := p.Resource("item")
	if it.Class != merge.FastForward || !hasConflict(it, merge.ConflictInvalid) || p.Clean() {
		t.Fatalf("item %+v", it)
	}
	if _, err := p.Apply(ctx); !errors.Is(err, merge.ErrConflicts) {
		t.Fatalf("apply: %v", err)
	}
	// A resolution that doesn't validate either stays a conflict.
	noErr(t, p.Resolve("item", client.PatchStep(ops(op("replace", "/n", "two")))))
	if _, err := p.Apply(ctx); !errors.Is(err, merge.ErrConflicts) || !it.NeedsPerson() {
		t.Fatalf("invalid resolution: %v %+v", err, it)
	}
	noErr(t, p.Resolve("item", client.PatchStep(ops(op("replace", "/n", 2)))))
	must(p.Apply(ctx))
	sameDoc(t, e.doc("m", "item"), map[string]any{"$schema": ref, "n": 2})
}

// Rebasing an e2e branch gives the successor its own keyring, replays
// re-encrypted under it, switches, and catches up exactly what is new.
func TestE2ERebase(t *testing.T) {
	e := newE3(t, map[string]any{"encryption": map[string]any{"level": "e2e"}})
	e.branch("r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("m", "cup", op("replace", "/title", "Cup!"))
	e.append("r7", "cup", op("replace", "/score", "3-3"))

	if _, err := merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7b"}); err == nil || !strings.Contains(err.Error(), "e2e") {
		t.Fatalf("rebase without keys: %v", err)
	}
	res := must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7b", Plan: merge.Options{E2E: e.x}}))
	if !res.Created || res.FirstResult == nil {
		t.Fatalf("rebase %+v", res)
	}
	kr, _ := must2(e.x.Keyring(ctx, "r7b"))
	if kr.NS != "r7b" {
		t.Fatalf("successor keyring %+v", kr)
	}
	sameDoc(t, e.doc("r7b", "derby"), map[string]any{"title": "Derby", "score": "1-0"})
	sameDoc(t, e.doc("r7b", "cup"), map[string]any{"title": "Cup!", "score": "3-3"})
	for _, k := range e.kids("r7b", "derby") {
		if k == "r7#1" {
			t.Fatal("the successor holds a patch set sealed under the old branch's key")
		}
	}

	// Resume and switch, with a change made meanwhile: without
	// merge.authors, the earlier replay still counts as the merge point (it
	// is the rebase), so only the new change replays.
	e.append("r7", "derby", op("add", "/late", true))
	res2 := must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7b", Switch: true, Plan: merge.Options{E2E: e.x}}))
	if !res2.Switched || res2.Created || res2.FirstResult == nil {
		t.Fatalf("switch %+v", res2)
	}
	if d := res2.First.Resource("derby"); d.Class != merge.Replay || d.Pair == nil || !d.Pair.Used || len(d.Steps) != 1 {
		t.Fatalf("derby %+v", d)
	}
	if c := res2.First.Resource("cup"); c.Class != merge.Merged {
		t.Fatalf("cup %+v", c)
	}
	sameDoc(t, e.doc("r7b", "derby"), map[string]any{"title": "Derby", "score": "1-0", "late": true})
}

// At E2 ids are over plaintext, so a fast-forward merge reproduces the
// branch's ids (§F.8).
func TestSealedFastForwardKeepsIDs(t *testing.T) {
	ks, err := keystore.New(keystore.Generate())
	noErr(t, err)
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("alice")).With(client.WithKeys(client.NewKeys(nil)))
	e := &env{t: t, s: s, c: c}
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed", "pad": true}, "merge": devAuthors}))
	nonced := func(ps ...map[string]any) []any {
		return append(ops(ps...), op("add", "/$nonce", seal.NewNonce()))
	}
	must(c.Create(ctx, "matches", "derby", nonced(op("add", "", map[string]any{"score": "0-0"}))))
	e.branch("matches", "r7")
	must(c.Append(ctx, "r7", "derby", e.head("r7", "derby").ID, nonced(op("replace", "/score", "1-0"))))
	must(c.Append(ctx, "r7", "derby", e.head("r7", "derby").ID, nonced(op("replace", "/score", "2-0"))))
	must(c.Create(ctx, "r7", "final", nonced(op("add", "", map[string]any{"title": "Final"}))))

	p := e.plan("matches", "r7", merge.Options{})
	if p.TargetLevel != "sealed" || p.Reencrypt {
		t.Fatalf("plan %+v", p)
	}
	wantClasses(t, p, map[string]merge.Class{"derby": merge.FastForward, "final": merge.FastForward})
	if d := p.Resource("derby"); len(d.Expected) != 2 {
		t.Fatalf("derby %+v", d)
	}
	must(p.Apply(ctx))
	for _, n := range []string{"derby", "final"} {
		if b, h := e.head("matches", n), e.head("r7", n); b.ID != h.ID {
			t.Fatalf("%s: base %s, branch %s", n, b.ID, h.ID)
		}
	}
	if d := e.doc("matches", "derby").(map[string]any); d["score"] != "2-0" {
		t.Fatalf("derby %v", d)
	}
}
