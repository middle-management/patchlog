package tree

import (
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
)

// A snapshot listed by pages reaches the graph whole, at its last page
// (stage): earlier pages are held, a first page drops pages held from an
// earlier attempt, and a snapshot of one page passes as it is.
func TestStageSnapshotPages(t *testing.T) {
	s := &Service{}
	units := func(names ...string) []follow.Unit {
		var us []follow.Unit
		for _, n := range names {
			us = append(us, follow.Unit{Entry: client.NSEntry{Resource: n, Kind: "head", Target: "t"}, Synthetic: true})
		}
		return us
	}
	page := func(after, more string, names ...string) *follow.Batch {
		return &follow.Batch{NS: "n", Snapshot: true, NewCheckpoint: "at", After: after, More: more, Units: units(names...)}
	}
	got := func(b *follow.Batch) string {
		var ns []string
		for _, u := range b.Units {
			ns = append(ns, u.Entry.Resource)
		}
		return fmt.Sprintf("%v after=%q more=%q replaces=%v", ns, b.After, b.More, b.Replaces())
	}
	if _, ok := s.stage(page("", "b", "a", "b")); ok {
		t.Fatal("a first page applied")
	}
	// The follower started again: the first page comes again.
	if _, ok := s.stage(page("", "b", "a", "b")); ok {
		t.Fatal("a first page applied")
	}
	if _, ok := s.stage(page("b", "d", "c", "d")); ok {
		t.Fatal("a middle page applied")
	}
	b, ok := s.stage(page("d", "", "e"))
	if !ok || got(b) != `[a b c d e] after="" more="" replaces=true` {
		t.Fatalf("whole snapshot %v: %s", ok, got(b))
	}
	if len(s.pending) != 0 {
		t.Fatalf("pages held after the last: %v", s.pending)
	}
	one := page("", "", "x")
	if b, ok := s.stage(one); !ok || b != one {
		t.Fatalf("one page: %v %s", ok, got(b))
	}
}
