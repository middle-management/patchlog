package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
)

// p29Engine is an engine with a key store and authentication disabled.
func p29Engine(t *testing.T) *Engine {
	t.Helper()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.DB(t), BlobStore: fileBlobs(t), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Limits: lim, Purger: discardPurger{}, KeyStore: ks})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func p29Req(ns string) Request {
	r := who
	r.NS = ns
	return r
}

// p29Status is the status of a core error, 0 for none.
func p29Status(t *testing.T, err error) (int, map[string]any) {
	t.Helper()
	if err == nil {
		return 0, nil
	}
	var ae *Error
	if !errors.As(err, &ae) {
		t.Fatal(err)
	}
	return ae.Status, ae.Body
}

func p29Sealed(t *testing.T, key []byte, kid, ns, name, parent string, patches []any) []any {
	t.Helper()
	b, err := seal.SealPatchSet(key, kid, ns, name, parent, jsonv.FromGo(patches))
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsonv.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return v.([]any)
}

func p29Add(path string, v any) map[string]any {
	return map[string]any{"op": "add", "path": path, "value": v}
}

// v0.73 Addendum E Levels, Changing it (ENC-38): a namespace may be raised
// to e2e from none, at-rest or sealed; from sealed, only with encryption.
// epoch the current one plus one (422 invalid at /encryption/epoch). The
// raise is recorded with what was in force before, and an e2e_epochs row
// begins the new epoch; writes from the raising entry on, its batch's
// items included, are sealed ops under that epoch.
func TestV073P29RaiseToE2E(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := p29Engine(t)
	raw := func(ns, name, parent string, patches []any) (*WriteResult, error) {
		return e.WriteResource(ctx, p29Req(ns), Item{Resource: name, IfMatch: parent, IfNoneMatch: parent == "", Steps: []Step{{Patches: patches}}})
	}
	raiseOf := func(ns string) *e2eRaise {
		var r *e2eRaise
		if err := e.read(ctx, func(t *tx) error { r = t.e2eRaiseOf(t.nsByName(ns)); return nil }); err != nil {
			t.Fatal(err)
		}
		return r
	}

	// From sealed: only to the current epoch plus one.
	cfg := mkNS(t, e, "s", map[string]any{"encryption": map[string]any{"level": "sealed", "pad": true}})
	w, err := raw("s", "d", "", []any{p29Add("", map[string]any{"n": 1.0}), p29Add("/$nonce", seal.NewNonce())})
	if err != nil {
		t.Fatal(err)
	}
	d1 := w.Items[0].IDs[0]
	if err := e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`INSERT INTO rotations_due (ns, since) VALUES (?, 0)`, t.nsByName("s").id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, enc := range []map[string]any{{"level": "e2e"}, {"level": "e2e", "epoch": 1.0}, {"level": "e2e", "epoch": 3.0}} {
		_, err := e.WriteConfig(ctx, p29Req("s"), ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "replace", "path": "/encryption", "value": enc}}})
		st, body := p29Status(t, err)
		errs, _ := body["errors"].([]any)
		if st != 422 || body["code"] != "invalid" || len(errs) != 1 || errs[0].(map[string]any)["pointer"] != "/encryption/epoch" {
			t.Fatalf("raise from sealed epoch 1 with %v: %d %v, want 422 invalid at /encryption/epoch", enc, st, body)
		}
	}
	if raiseOf("s") != nil {
		t.Fatal("a refused raise was recorded")
	}
	rw, err := e.WriteConfig(ctx, p29Req("s"), ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 2.0}}}})
	if err != nil {
		t.Fatalf("raise from sealed with epoch 2: %v", err)
	}
	r := raiseOf("s")
	if r == nil || r.level != levelSealed || r.epoch != 1 || !r.pad || r.id.String() != rw.NSID || r.seq == 0 {
		t.Fatalf("raise of s %+v, want from sealed at epoch 1 with pad, at entry %s", r, rw.NSID)
	}
	var epochs, due int
	if err := e.read(ctx, func(t *tx) error {
		n := t.nsByName("s")
		t.must(t.QueryRow(`SELECT COUNT(*) FROM e2e_epochs WHERE ns = ? AND epoch = 2`, n.id).Scan(&epochs))
		t.must(t.QueryRow(`SELECT COUNT(*) FROM rotations_due WHERE ns = ?`, n.id).Scan(&due))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if epochs != 1 || due != 0 {
		t.Fatalf("after the raise: %d e2e_epochs rows for epoch 2, %d rotations due; want 1 and 0", epochs, due)
	}
	// Writes are sealed ops under the new epoch from then on.
	k2 := seal.NewKey()
	if st, body := p29Status(t, second(raw("s", "d", d1, []any{p29Add("/n", 2.0)}))); st != 422 || body["code"] != "invalid" {
		t.Fatalf("plaintext append after the raise: %d %v, want 422 invalid", st, body)
	}
	if st, _ := p29Status(t, second(raw("s", "d", d1, p29Sealed(t, k2, "s#1", "s", "d", d1, []any{p29Add("/n", 2.0)})))); st != 422 {
		t.Fatalf("append sealed under the epoch before the raise: %d, want 422", st)
	}
	if _, err := raw("s", "d", d1, p29Sealed(t, k2, "s#2", "s", "d", d1, []any{p29Add("/n", 2.0)})); err != nil {
		t.Fatalf("sealed append under s#2: %v", err)
	}

	// From none, in a batch: its items are judged under the raise.
	pcfg := mkNS(t, e, "p", map[string]any{})
	w, err = raw("p", "d", "", []any{p29Add("", map[string]any{"n": 1.0})})
	if err != nil {
		t.Fatal(err)
	}
	p1 := w.Items[0].IDs[0]
	raise := &ConfigChange{IfMatch: pcfg, Patches: []any{p29Add("/encryption", map[string]any{"level": "e2e"})}}
	if st, _ := p29Status(t, second(e.Batch(ctx, p29Req("p"), []Item{{Resource: "d", IfMatch: p1, Steps: []Step{{Patches: []any{p29Add("/n", 2.0)}}}}}, raise, nil, false))); st != 422 {
		t.Fatalf("a plaintext item in the raising batch: %d, want 422", st)
	}
	k1 := seal.NewKey()
	bw, err := e.Batch(ctx, p29Req("p"), []Item{{Resource: "d", IfMatch: p1, Steps: []Step{{Patches: p29Sealed(t, k1, "p#1", "p", "d", p1, []any{p29Add("/n", 2.0)})}}}}, raise, nil, false)
	if err != nil {
		t.Fatalf("a sealed item under p#1 in the raising batch: %v", err)
	}
	if r := raiseOf("p"); r == nil || r.level != levelNone || r.epoch != 0 || r.pad || r.id.String() != bw.NSID {
		t.Fatalf("raise of p %+v, want from none at the batch entry %s", r, bw.NSID)
	}

	// From at-rest, any epoch from 1 starts it (F-E1).
	acfg := mkNS(t, e, "a", map[string]any{"encryption": map[string]any{"level": "at-rest"}})
	if _, err := e.WriteConfig(ctx, p29Req("a"), ConfigChange{IfMatch: acfg, Patches: []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 4.0}}}}); err != nil {
		t.Fatalf("raise from at-rest to epoch 4: %v", err)
	}
	if r := raiseOf("a"); r == nil || r.level != levelAtRest {
		t.Fatalf("raise of a %+v", r)
	}
	// A namespace e2e from its creation has no raise.
	mkNS(t, e, "c", map[string]any{"encryption": map[string]any{"level": "e2e"}})
	if r := raiseOf("c"); r != nil {
		t.Fatalf("raise of c %+v, want none", r)
	}
}

func second[A any](_ A, err error) error { return err }

// v0.73 §E.3.1, Addendum E Levels (ENC-22, ENC-38): after a raise from
// sealed, a prune snapshot whose newest content revision is from before
// the raise is sealed under the epoch that revision is served under, not
// the epoch in force; the server checks it (422 invalid).
func TestV073P29SnapshotKidBeforeRaise(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	now := &p29Clock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	e, err := Open(Options{Path: pgtest.DB(t), BlobStore: fileBlobs(t), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}, KeyStore: ks, Archiver: p29Archiver{}, Now: now.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	cfg := mkNS(t, e, "s", map[string]any{"encryption": map[string]any{"level": "sealed"}})
	write := func(parent string, patches []any) string {
		t.Helper()
		w, err := e.WriteResource(ctx, p29Req("s"), Item{Resource: "d", IfMatch: parent, IfNoneMatch: parent == "", Steps: []Step{{Patches: patches}}})
		if err != nil {
			t.Fatal(err)
		}
		return w.Items[0].IDs[0]
	}
	w1 := write("", []any{p29Add("", map[string]any{"n": 1.0}), p29Add("/$nonce", seal.NewNonce())})
	w2 := write(w1, []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}, map[string]any{"op": "replace", "path": "/$nonce", "value": seal.NewNonce()}})
	if _, err := e.WriteConfig(ctx, p29Req("s"), ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e"}}}}); err == nil {
		t.Fatal("raise from sealed without a new epoch")
	}
	if _, err := e.WriteConfig(ctx, p29Req("s"), ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 2.0}}}}); err != nil {
		t.Fatalf("raise from sealed with epoch 2: %v", err)
	}
	now.Advance(10 * time.Minute) // past what a prune protects
	key := seal.NewKey()          // the server checks the header only
	snap := func(kid string) string {
		t.Helper()
		kr, err := seal.ResourceKey(key, "s", "d")
		if err != nil {
			t.Fatal(err)
		}
		jwe, err := seal.SealSnapshot(kr, kid, "s", "d", w2, jsonv.FromGo(map[string]any{"n": 2.0}))
		if err != nil {
			t.Fatal(err)
		}
		return jwe
	}
	if st, body := p29Status(t, second(e.Prune(ctx, p29Req("s"), "d", PruneRequest{Horizon: w2, Snapshot: snap("s#2")}))); st != 422 || body["code"] != "invalid" || !strings.Contains(fmt.Sprint(body["message"]), "epoch 2, not 1") {
		t.Fatalf("snapshot of pre-raise content under the epoch in force: %d %v, want 422 invalid", st, body)
	}
	if _, err := e.Prune(ctx, p29Req("s"), "d", PruneRequest{Horizon: w2, Snapshot: snap("s#1")}); err != nil {
		t.Fatalf("snapshot of pre-raise content under the epoch it is served under: %v", err)
	}
}

// p29Archiver takes every archive and keeps nothing: an e2e prune needs a
// destination (§8.6).
type p29Archiver struct{}

func (p29Archiver) Check(string) error { return nil }
func (p29Archiver) Write(_ context.Context, _, key string, b *ArchiveBundle) (string, error) {
	return "mem:" + key, b.Entries(func(ArchiveEntry) error { return nil })
}
func (p29Archiver) Delete(context.Context, string) error { return nil }
func (p29Archiver) Open(context.Context, string) (io.ReadCloser, error) {
	return nil, errors.New("p29Archiver keeps nothing")
}

// p29Clock is an engine clock that moves only when told.
type p29Clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *p29Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *p29Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}
