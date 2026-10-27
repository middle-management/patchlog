package client_test

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// p35Raise raises e to e2e at epoch and writes its keyring.
func (v *p29Env) p35Raise(t *testing.T, enc map[string]any) {
	t.Helper()
	ctx := context.Background()
	h := must(v.c.NSHead(ctx, "e"))
	must(v.c.PatchConfig(ctx, "e", h.Config, ops(op("add", "/encryption", enc))))
	must(v.x.InitKeyring(ctx, "e"))
}

// v0.73 Addendum E Levels (ENC-39, F-E1 default), §7.1 Paging: an E3
// reader folds across a raise from sealed. A revision from before it is
// its document served sealed as at E2, under the epoch before the raise
// (PreRaise); one written end to end folds from the last revision from
// before the raise, or from the last live one before a tombstone, whose
// entry, sealed as at E2, the range holds. The keys of the epochs before
// the raise come from /keys as at E2 (here held from before the raise).
func TestV073P35FoldAcrossRaiseFromSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, map[string]any{"level": "sealed", "pad": true})
	r1 := must(v.c.Create(ctx, "e", "d", ops(op("add", "", map[string]any{"n": 1.0}), op("add", "/$nonce", seal.NewNonce())))).ID
	r2 := must(v.c.Append(ctx, "e", "d", r1, ops(op("replace", "/n", 2.0), op("replace", "/$nonce", seal.NewNonce())))).ID
	t1 := must(v.c.Create(ctx, "e", "t", ops(op("add", "", map[string]any{"m": 1.0}), op("add", "/$nonce", seal.NewNonce())))).ID
	tomb := must(v.c.Delete(ctx, "e", "t", t1)).ID
	raw := v.s.Client(t, client.WithBearer(v.k.Grant(t, v.s.Now(), "user:a", []string{"e"}, p29Verbs, nil)))
	for _, k := range must(raw.FetchKeys(ctx, "e", nil, nil)) {
		v.x.AddKey(k.Kid, k.Key)
	}
	v.p35Raise(t, map[string]any{"level": "e2e", "epoch": 2.0})

	d := must(v.x.DocE2E(ctx, "e", "d", r2))
	if !d.PreRaise || d.Plain || d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("revision from before the raise: %+v", d)
	}
	r3 := must(v.x.AppendSealed(ctx, "e", "d", r2, ops(op("replace", "/n", 3.0)))).ID
	d = must(v.x.DocE2E(ctx, "e", "d", r3))
	if d.Value.(map[string]any)["n"] != 3.0 || len(d.Flagged) != 0 || d.ValidID != r3 {
		t.Fatalf("fold across the raise: %+v", d)
	}
	t2 := must(v.x.RestoreSealed(ctx, "e", "t", tomb, ops(op("replace", "/m", 2.0)))).ID
	d = must(v.x.DocE2E(ctx, "e", "t", t2))
	if d.Value.(map[string]any)["m"] != 2.0 || len(d.Flagged) != 0 {
		t.Fatalf("fold of a restore over a tombstone from before the raise: %+v", d)
	}
	// A prune snapshot of the fold seals under the epoch in force: the
	// range holds a revision written end to end (§E.3.1).
	must(v.x.PruneE2E(ctx, "e", "d", r3))
	if d := must(v.x.DocE2E(ctx, "e", "d", r3)); d.Value.(map[string]any)["n"] != 3.0 {
		t.Fatalf("after the prune: %+v", d)
	}
}

// v0.73 Addendum E Levels (ENC-39, F-E1 default): after a raise from none
// an E3 reader takes a revision from before the raise in the clear, and
// folds a later one from it.
func TestV073P35FoldAcrossRaiseFromNone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, map[string]any{"level": "at-rest"})
	r1 := must(v.c.Create(ctx, "e", "d", ops(op("add", "", map[string]any{"n": 1.0})))).ID
	v.p35Raise(t, map[string]any{"level": "e2e", "epoch": 1.0})
	d := must(v.x.DocE2E(ctx, "e", "d", r1))
	if !d.PreRaise || d.Value.(map[string]any)["n"] != 1.0 {
		t.Fatalf("revision from before the raise: %+v", d)
	}
	r2 := must(v.x.AppendSealed(ctx, "e", "d", r1, ops(op("replace", "/n", 2.0)))).ID
	if d := must(v.x.DocE2E(ctx, "e", "d", r2)); d.Value.(map[string]any)["n"] != 2.0 || len(d.Flagged) != 0 {
		t.Fatalf("fold across the raise: %+v", d)
	}
}

// v0.73 §6.1, Addendum E Levels (CIS-24, w3x carry-over): an E3 reader
// validates a document whose $schema pins a revision from before the
// namespace's raise from sealed: /rev serves it sealed as at E2, and the
// view opens it with the key of its epoch.
func TestV073P35ValidatesAgainstPreRaiseSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, map[string]any{"level": "sealed"})
	sch := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
		"properties": map[string]any{"n": map[string]any{"type": "number"}}, "required": []any{"n"}}
	s1 := must(v.c.Create(ctx, "e", "m", ops(op("add", "", sch), op("add", "/$nonce", seal.NewNonce())))).ID
	raw := v.s.Client(t, client.WithBearer(v.k.Grant(t, v.s.Now(), "user:a", []string{"e"}, p29Verbs, nil)))
	for _, k := range must(raw.FetchKeys(ctx, "e", nil, nil)) {
		v.x.AddKey(k.Kid, k.Key)
	}
	v.p35Raise(t, map[string]any{"level": "e2e", "epoch": 2.0})
	good := must(v.x.CreateSealed(ctx, "e", "good", ops(op("add", "", map[string]any{"$schema": "/r/e/m/rev/" + s1, "n": 1.0})))).ID
	if d := must(v.x.DocE2E(ctx, "e", "good", good)); len(d.Flagged) != 0 {
		t.Fatalf("a valid document flagged: %+v", d.Flagged)
	}
	// A writer validates before it seals (§E.3.2).
	if _, err := v.x.AppendSealed(ctx, "e", "good", good, ops(op("replace", "/n", "x"))); err == nil || !strings.Contains(err.Error(), "doesn't validate") {
		t.Fatalf("an invalid document written: %v", err)
	}
}
