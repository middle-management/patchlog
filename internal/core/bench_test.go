package core

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// Small writes and reads, for comparing the storage dialects:
//
//	go test ./internal/core -run '^$' -bench .
//	PATCHLOG_TEST_PG=postgres://… go test ./internal/core -run '^$' -bench .

func benchEngine(b *testing.B, read string) *Engine {
	b.Helper()
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.DB(b), BlobDir: b.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}, Limits: lim})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { e.Close() })
	genesis := []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": read}}}
	if _, err := e.WriteConfig(context.Background(), Request{NS: "b", Cred: Credentials{Author: "a"}}, ConfigChange{IfNoneMatch: true, Patches: genesis}); err != nil {
		b.Fatal(err)
	}
	return e
}

func benchWrite(e *Engine, name, ifMatch string, i int) (string, error) {
	it := Item{Resource: name, IfMatch: ifMatch, IfNoneMatch: ifMatch == ""}
	op := "replace"
	if ifMatch == "" {
		op = "add"
	}
	it.Steps = []Step{{Patches: []any{map[string]any{"op": op, "path": "", "value": map[string]any{"n": float64(i)}}}}}
	r, err := e.WriteResource(context.Background(), Request{NS: "b", Cred: Credentials{Author: "a"}}, it)
	if err != nil {
		return "", err
	}
	return r.Items[0].IDs[0], nil
}

// BenchmarkWrite appends to one resource, one write at a time.
func BenchmarkWrite(b *testing.B) {
	e := benchEngine(b, "public")
	head, err := benchWrite(e, "r", "", 0)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if head, err = benchWrite(e, "r", head, i+1); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWriteParallel appends from several goroutines, each to a
// resource of its own namespace: serialised in SQLite, in parallel on
// Postgres (one lock per namespace).
func BenchmarkWriteParallel(b *testing.B) {
	e := benchEngine(b, "public")
	var next atomic.Int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ns := fmt.Sprint("p", next.Add(1))
		genesis := []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": "public"}}}
		if _, err := e.WriteConfig(context.Background(), Request{NS: ns, Cred: Credentials{Author: "a"}}, ConfigChange{IfNoneMatch: true, Patches: genesis}); err != nil {
			b.Error(err)
			return
		}
		head, i := "", 0
		for pb.Next() {
			it := Item{Resource: "r", IfMatch: head, IfNoneMatch: head == ""}
			op := "replace"
			if head == "" {
				op = "add"
			}
			it.Steps = []Step{{Patches: []any{map[string]any{"op": op, "path": "", "value": map[string]any{"n": float64(i)}}}}}
			r, err := e.WriteResource(context.Background(), Request{NS: ns, Cred: Credentials{Author: "a"}}, it)
			if err != nil {
				b.Error(err)
				return
			}
			head = r.Items[0].IDs[0]
			i++
		}
	})
}

// BenchmarkReadHead resolves a head pointer in a namespace that isn't
// public, so every read opens a transaction (no transaction-free cache).
func BenchmarkReadHead(b *testing.B) {
	e := benchEngine(b, "grant")
	for i := 0; i < 10; i++ {
		if _, err := benchWrite(e, fmt.Sprint("r", i), "", i); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, err := e.ResourceHead(context.Background(), "b", fmt.Sprint("r", i%10), Credentials{Author: "a"}); err != nil {
				b.Error(err)
				return
			}
			i++
		}
	})
}
