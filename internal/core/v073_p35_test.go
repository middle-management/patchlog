package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

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

// v0.73 §9, Addendum E Levels, Changing it (RH-47): a raise into sealed
// purges ns:{ns}, whatever the read setting; an epoch change doesn't.
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
	// v0.78: a raise to e2e is refused (Addendum E Levels) and purges
	// nothing; a raise into sealed still purges.
	if _, err := e.WriteConfig(ctx, p29Req("s"), ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 3.0}}}}); err == nil {
		t.Fatal("a raise from sealed to e2e was applied")
	}
	if tags := p.take(); slices.Contains(tags, "ns:s") {
		t.Fatalf("a refused raise to e2e purged %v", tags)
	}
	pcfg := mkNS(t, e, "p", map[string]any{"read": "grant"})
	p.take()
	if _, err := e.WriteConfig(ctx, p29Req("p"), ConfigChange{IfMatch: pcfg, Patches: []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}}}}); err != nil {
		t.Fatal(err)
	}
	if tags := p.take(); !slices.Contains(tags, "ns:p") {
		t.Fatalf("a raise to sealed purged %v, not ns:p", tags)
	}
}

// p35Archiver keeps the entries of the archives written to it.
type p35Archiver struct {
	mu      sync.Mutex
	entries []ArchiveEntry
}

func (*p35Archiver) Check(string) error { return nil }
func (a *p35Archiver) Write(_ context.Context, _, key string, b *ArchiveBundle) (string, error) {
	return "mem:" + key, b.Entries(func(e ArchiveEntry) error {
		a.mu.Lock()
		a.entries = append(a.entries, e)
		a.mu.Unlock()
		return nil
	})
}
func (*p35Archiver) Delete(context.Context, string) error { return nil }
func (*p35Archiver) Open(context.Context, string) (io.ReadCloser, error) {
	return nil, errors.New("p35Archiver opens nothing")
}

// §E.2.2 "stored once, served forever", §8.6 (P26 carry-over): a prune
// keeps the stored sealing of a schema revision that documents still pin
// and that an earlier prune left below its horizon with its document kept
// (the preserved set), as it keeps the document: the revision is served
// with the same bytes after the second prune.
func TestV073P35PrunePreservedSchemaKeepsSealing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	now := &p29Clock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}, KeyStore: ks, Archiver: &p35Archiver{}, Now: now.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	mkNS(t, e, "s", map[string]any{"encryption": map[string]any{"level": "sealed"}})
	mkNS(t, e, "p", map[string]any{})
	sch := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}
	var revs []string
	parent := ""
	for i := 0; i < 4; i++ {
		ps := []any{map[string]any{"op": "replace", "path": "/$nonce", "value": seal.NewNonce()}, p29Add("/title", fmt.Sprint(i))}
		if parent == "" {
			ps = []any{p29Add("", sch), p29Add("/$nonce", seal.NewNonce())}
		}
		w, err := e.WriteResource(ctx, p29Req("s"), Item{Resource: "m", IfMatch: parent, IfNoneMatch: parent == "", Steps: []Step{{Patches: ps}}})
		if err != nil {
			t.Fatal(err)
		}
		parent = w.Items[0].IDs[0]
		revs = append(revs, parent)
	}
	if _, err := e.WriteResource(ctx, p29Req("p"), Item{Resource: "x", IfNoneMatch: true, Steps: []Step{{Patches: []any{p29Add("", map[string]any{"$schema": "/r/s/m/rev/" + revs[0]})}}}}); err != nil {
		t.Fatal(err)
	}
	now.Advance(10 * time.Minute)
	if _, err := e.Prune(ctx, p29Req("s"), "m", PruneRequest{Horizon: revs[2]}); err != nil {
		t.Fatal(err)
	}
	a, err := e.ResourceRev(ctx, "s", "m", revs[0], Credentials{})
	if err != nil || a.Status != 200 || a.JWE == "" {
		t.Fatalf("pinned schema revision below the horizon: %v %+v", err, a)
	}
	now.Advance(10 * time.Minute)
	if _, err := e.Prune(ctx, p29Req("s"), "m", PruneRequest{Horizon: revs[3]}); err != nil {
		t.Fatal(err)
	}
	b, err := e.ResourceRev(ctx, "s", "m", revs[0], Credentials{})
	if err != nil || b.Status != 200 || b.JWE != a.JWE {
		t.Fatalf("after the second prune: %v %+v, want the stored sealing %s", err, b, a.JWE)
	}
}
