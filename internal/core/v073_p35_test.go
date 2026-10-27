package core

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
)

// p35Purger records the cache tags purged.
type p35Purger struct {
	mu   sync.Mutex
	tags []string
}

func (p *p35Purger) PurgeTags(tags []string) {
	p.mu.Lock()
	p.tags = append(p.tags, tags...)
	p.mu.Unlock()
}

// take returns the tags purged since the last call.
func (p *p35Purger) take() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.tags
	p.tags = nil
	return t
}

// p35Engine is p29Engine with purges recorded.
func p35Engine(t *testing.T, p Purger) *Engine {
	t.Helper()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Limits: lim, Purger: p, KeyStore: ks})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// v0.73 §9, Addendum E Levels, Changing it (RH-47): any raise into sealed
// or e2e purges ns:{ns}, a raise from sealed to e2e included, whatever the
// read setting; an epoch change doesn't.
func TestV073P35RaisePurgesNamespaceTag(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := &p35Purger{}
	e := p35Engine(t, p)
	cfg := mkNS(t, e, "s", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}})
	enc := func(v map[string]any) string {
		t.Helper()
		w, err := e.WriteConfig(ctx, p29Req("s"), ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "replace", "path": "/encryption", "value": v}}})
		if err != nil {
			t.Fatal(err)
		}
		return w.ConfigID
	}
	p.take()
	cfg = enc(map[string]any{"level": "sealed", "epoch": 2.0})
	if slices.Contains(p.take(), "ns:s") {
		t.Fatal("an epoch change purged ns:s")
	}
	enc(map[string]any{"level": "e2e", "epoch": 3.0})
	if tags := p.take(); !slices.Contains(tags, "ns:s") {
		t.Fatalf("a raise from sealed to e2e purged %v, not ns:s", tags)
	}
}

// v0.73 Addendum E Levels, §8.5: a namespace raised from sealed and then
// purged answers 410 purged for its namespace documents and log ranges
// from before the raise, which the purge's destroyed epoch keys sealed,
// rather than serving them in the clear; those after it stay readable as
// at e2e.
func TestV073P35PurgedPreRaiseSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := p35Engine(t, discardPurger{})
	cfg := mkNS(t, e, "s", map[string]any{"encryption": map[string]any{"level": "sealed"}})
	if _, err := e.WriteResource(ctx, p29Req("s"), Item{Resource: "d", IfNoneMatch: true, Steps: []Step{{Patches: []any{p29Add("", map[string]any{"n": 1.0}), p29Add("/$nonce", seal.NewNonce())}}}}); err != nil {
		t.Fatal(err)
	}
	h, err := e.NamespaceHead(ctx, "s", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	rw, err := e.WriteConfig(ctx, p29Req("s"), ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 2.0}}}})
	if err != nil {
		t.Fatal(err)
	}
	fw, err := e.WriteConfig(ctx, p29Req("s"), ConfigChange{IfMatch: rw.ConfigID, Patches: []any{p29Add("/frozen", true)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.PurgeNamespace(ctx, p29Req("s"), fw.NSID, false); err != nil {
		t.Fatal(err)
	}
	if st, body := p29Status(t, second(e.NamespaceRev(ctx, "s", h.Head, Credentials{}))); st != 410 || body["code"] != "purged" {
		t.Fatalf("namespace document from before the raise after a purge: %d %v", st, body)
	}
	if st, body := p29Status(t, second(e.NamespaceLog(ctx, "s", h.Head, "", 0, Credentials{}))); st != 410 || body["code"] != "purged" {
		t.Fatalf("range from before the raise after a purge: %d %v", st, body)
	}
	if lg, err := e.NamespaceLog(ctx, "s", "", h.Head, 0, Credentials{}); err != nil || lg.Status != 200 || lg.Sealed || len(lg.Entries) == 0 {
		t.Fatalf("range after the raise after a purge: %v %+v", err, lg)
	}
}
