package core

import (
	"context"
	"slices"
	"testing"

	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/rules"
)

// v0.88 §6.6 Validation work ("Each read request … gets one budget,
// shared by every check it makes"; Grant scope scenario 79): the read
// checks of one read transaction draw on one budget, or on the one its
// context carries (ReadBudget) across transactions, as a long-poll's
// fetches do; a list or an exchange's grant has its own (ownReadScope).
// Until v0.88 each read check had a budget of its own.
func TestV088OneReadBudgetPerRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r, err := rules.Compile(map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{
		"allOf": []any{map[string]any{"type": "string"}, map[string]any{"minLength": 1.0}, map[string]any{"maxLength": 9.0}}}})
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]any{"resource": "x"}
	m := rules.Budget(1 << 20)
	r.Passes(env, m)
	steps := m.Steps
	if steps < 2 {
		t.Fatalf("the rule takes %d steps", steps)
	}
	ks, _ := keystore.New(keystore.Generate())
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		MaxValidationSteps: steps + steps/2, KeyStore: ks})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	twice := func(ctx context.Context) (first, second, own bool) {
		if err := e.read(ctx, func(t *tx) error {
			first, second = t.readRule(r, env), t.readRule(r, env)
			done := t.ownReadScope()
			own = t.readRule(r, env)
			done()
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	if first, second, own := twice(ctx); !first || second || !own {
		t.Fatalf("one transaction: %v %v, own scope %v; want the second check to run out, the own scope not", first, second, own)
	}
	bctx := e.ReadBudget(ctx)
	if first, _, _ := twice(bctx); !first {
		t.Fatal("the first check on a fresh request budget failed")
	}
	if first, _, _ := twice(bctx); first {
		t.Fatal("a second transaction of one request got a fresh budget")
	}
}

// v0.88 §7.9 URLs ("Ranges are immutable but for purges and archive
// restores since"): a write that may change a cached filtered range, a
// purge or a restore that brings documents back, purges ns:{ns}, the tag
// those ranges carry, once a view has been recorded in the namespace, and
// only then (tagFilteredRanges, called by purgeApply and RestoreResource).
func TestV088RestoreTagsFilteredRanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := &p35Purger{}
	e := p35Engine(t, p)
	mkNS(t, e, "m", map[string]any{"read": "grant"})
	tags := func() []string {
		var out []string
		if err := e.update(ctx, func(t *tx) error {
			t.tags = nil
			t.tagFilteredRanges(t.nsByName("m"))
			out = slices.Clone(t.tags)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := tags(); len(got) != 0 {
		t.Fatalf("no view recorded: %v", got)
	}
	if err := e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`INSERT INTO filtered_views (ns, view, subjects, kid, pub, roles, block_rules, read_scope, principal, digest, entry, conf, filter, exp)
			VALUES ('m', 'v', '[]', 'k', '', '[]', '[]', 0, '{}', 'd', '', 0, '{}', 0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := tags(); !slices.Equal(got, []string{"ns:m"}) {
		t.Fatalf("a view recorded: %v, want [ns:m]", got)
	}
}
