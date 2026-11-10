package core

import (
	"context"
	"errors"
	"io"
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
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
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

func second[A any](_ A, err error) error { return err }

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
