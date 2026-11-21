package core

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
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

// v0.88 §G.1 ("only import batches by such a principal count, under a
// grant that may purge the names they write"; Grant scope scenario 87,
// FED-26): an import batch records, for following, only the names its
// grant may purge, with its principal as their importer, and one whose
// grant may purge none records no follow at all. A rule refusing the
// purge of one name keeps that name out.
func TestV088ImportRecordsOnlyPurgeableNames(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := p35Engine(t, &p35Purger{})
	mkNS(t, e, "m", map[string]any{"read": "grant"})
	src := map[string]any{"origin": "https://staging.example", "ns": "m", "at": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bundle": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	items := func(names ...string) []*itemState {
		var out []*itemState
		for _, n := range names {
			out = append(out, &itemState{Item: Item{Resource: n}})
		}
		return out
	}
	verified := func(can ...string) *actor {
		v := &grant.Verified{Grant: &grant.Grant{}, Principal: grant.Principal{ID: "svc:importer"}, Can: map[string]bool{}}
		for _, c := range can {
			v.Can[c] = true
		}
		return &actor{principal: v.Principal, verified: v}
	}
	notB := verified("create", "purge")
	notB.verified.BlockRules = []any{map[string]any{"not": map[string]any{"all": []any{
		map[string]any{"op": "test", "path": "/action", "value": "purge"},
		map[string]any{"op": "test", "path": "/resource", "value": "b"}}}}}
	recorded := func(a *actor, names ...string) (follows int, rows []string) {
		if err := e.update(ctx, func(t *tx) error {
			n := t.nsByName("m")
			if _, err := t.Exec(`DELETE FROM purge_follow_names`); err != nil {
				return err
			}
			if _, err := t.Exec(`DELETE FROM purge_follows`); err != nil {
				return err
			}
			t.recordImport(n, a, src, items(names...))
			t.must(t.QueryRow(`SELECT COUNT(*) FROM purge_follows`).Scan(&follows))
			q, err := t.Query(`SELECT name, importer FROM purge_follow_names ORDER BY name`)
			if err != nil {
				return err
			}
			defer q.Close()
			for q.Next() {
				var name, imp string
				t.must(q.Scan(&name, &imp))
				rows = append(rows, name+" "+imp)
			}
			return q.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	if f, rows := recorded(verified("create"), "a", "b"); f != 0 || len(rows) != 0 {
		t.Fatalf("a grant without purge: %d follows, %v", f, rows)
	}
	if f, rows := recorded(notB, "a", "b"); f != 1 || !slices.Equal(rows, []string{"a svc:importer"}) {
		t.Fatalf("a grant whose rules refuse the purge of b: %d follows, %v", f, rows)
	}
}

// v0.88 §7.7 ("each a positive whole number of milliseconds"): an
// interval under a millisecond, or with a fraction of one, is refused when
// the engine opens; a whole one is taken.
func TestV088LongPollIntervalWholeMilliseconds(t *testing.T) {
	t.Parallel()
	for _, d := range []time.Duration{time.Microsecond, 1500 * time.Microsecond, -time.Second} {
		if e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, LongPollInterval: d}); err == nil {
			e.Close()
			t.Errorf("long-poll interval %v: opened", d)
		}
	}
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, LongPollInterval: 1500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
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
