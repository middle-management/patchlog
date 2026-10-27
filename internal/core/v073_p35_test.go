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
	e, err := Open(Options{Path: pgtest.DB(t), BlobStore: fileBlobs(t), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
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

// v0.73 §D.4, Addendum E Levels (w3x carry-over): history pruned before a
// raise from sealed and restored after it is served as the rest of what
// was stored before the raise, sealed under the epoch before it; the
// snapshots the restore rebuilds never reach a read of what was written
// end to end, which folds.
func TestV073P35RestoredPreRaiseRangeStaysSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	now := &p29Clock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	arch := &p35Archiver{}
	e, err := Open(Options{Path: pgtest.DB(t), BlobStore: fileBlobs(t), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}, KeyStore: ks, Archiver: arch, Now: now.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	cfg := mkNS(t, e, "s", map[string]any{"encryption": map[string]any{"level": "sealed"}})
	var revs []string
	parent := ""
	for i := 1; i <= 3; i++ {
		ps := []any{p29Add("/$nonce", seal.NewNonce()), p29Add("/n", float64(i))}
		if parent == "" {
			ps = []any{p29Add("", map[string]any{"n": 1.0}), p29Add("/$nonce", seal.NewNonce())}
		}
		w, err := e.WriteResource(ctx, p29Req("s"), Item{Resource: "d", IfMatch: parent, IfNoneMatch: parent == "", Steps: []Step{{Patches: ps}}})
		if err != nil {
			t.Fatal(err)
		}
		parent = w.Items[0].IDs[0]
		revs = append(revs, parent)
	}
	now.Advance(10 * time.Minute)
	if _, err := e.Prune(ctx, p29Req("s"), "d", PruneRequest{Horizon: revs[2]}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.WriteConfig(ctx, p29Req("s"), ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 2.0}}}}); err != nil {
		t.Fatal(err)
	}
	r4w, err := e.WriteResource(ctx, p29Req("s"), Item{Resource: "d", IfMatch: revs[2], Steps: []Step{{Patches: p29Sealed(t, seal.NewKey(), "s#2", "s", "d", revs[2], []any{p29Add("/n", 4.0)})}}})
	if err != nil {
		t.Fatal(err)
	}
	r4 := r4w.Items[0].IDs[0]
	if rv, err := e.ResourceRev(ctx, "s", "d", revs[0], Credentials{}); err != nil || rv.Status != 410 {
		t.Fatalf("pruned revision before the restore: %v %+v", err, rv)
	}
	res, err := e.RestoreResource(ctx, "s", "d", func(yield func(ArchiveEntry) error) error {
		for _, en := range arch.entries {
			if err := yield(en); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil || res.Restored != 2 {
		t.Fatalf("restore: %v %+v", err, res)
	}
	for _, id := range revs {
		rv, err := e.ResourceRev(ctx, "s", "d", id, Credentials{})
		if err != nil || rv.Status != 200 || rv.JWE == "" || rv.Doc != nil || kidOf(rv.JWE) != "s#1" {
			t.Fatalf("restored revision %s from before the raise: %v %+v", id, err, rv)
		}
	}
	lg, err := e.ResourceLog(ctx, "s", "d", r4, "", 100, Credentials{})
	if err != nil || !lg.Sealed || len(lg.EntryJWEs) != 3 || !lg.More || lg.Last != revs[2] {
		t.Fatalf("restored range: %v %+v", err, lg)
	}
	rv, err := e.ResourceRev(ctx, "s", "d", r4, Credentials{})
	if err != nil || rv.Status != 302 || !rv.Fold || rv.FoldSince != revs[2] || rv.Doc != nil || rv.JWE != "" {
		t.Fatalf("revision written end to end: %v %+v", err, rv)
	}
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
	e, err := Open(Options{Path: pgtest.DB(t), BlobStore: fileBlobs(t), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
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
