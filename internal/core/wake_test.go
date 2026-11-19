package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// isOpen reports whether a waiter's channel is still open.
func isOpen(c <-chan struct{}) bool {
	select {
	case <-c:
		return false
	default:
		return true
	}
}

// woken waits up to d for a waiter's channel to close: on Postgres the
// tailer's wake-ups come a poll later than the local commit's.
func woken(c <-chan struct{}, d time.Duration) bool {
	select {
	case <-c:
		return true
	case <-time.After(d):
		return false
	}
}

// settle lets the tailer, on Postgres, see what has committed, so a wake-up
// it would publish has been published.
func settle() {
	if pgtest.Enabled() {
		time.Sleep(5 * tailEvery)
	}
}

// A resource's live readers are woken by the commits naming it, and by
// those concerning the whole namespace, and not by writes to the
// namespace's other resources (§7.7; hub, entryResources). The
// namespace's own readers are woken by every commit.
func TestWaitResource(t *testing.T) {
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	cfg := mkNS(t, e, "n", map[string]any{"read": "public"})
	heads := map[string]string{}
	for _, name := range []string{"a", "b", "c", "other"} {
		id, err := put(e, "n", name, "", 0)
		if err != nil {
			t.Fatal(err)
		}
		heads[name] = id
	}
	settle()

	wa, wb, wc := e.WaitResource("n", "a"), e.WaitResource("n", "b"), e.WaitResource("n", "c")
	wns := e.Wait("n")
	// Writes to another resource: single writes and a batch.
	for i := 1; i <= 20; i++ {
		id, err := put(e, "n", "other", heads["other"], i)
		if err != nil {
			t.Fatal(err)
		}
		heads["other"] = id
	}
	r := who
	r.NS = "n"
	if _, err := e.Batch(ctx, r, []Item{
		{Resource: "x", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}},
		{Resource: "y", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}},
	}, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	settle()
	if !woken(wns, 5*time.Second) {
		t.Fatal("the namespace's waiter wasn't woken")
	}
	if !isOpen(wa) || !isOpen(wb) || !isOpen(wc) {
		t.Fatal("a resource waiter was woken by writes to other resources")
	}

	// A batch naming a wakes a's waiter only.
	if _, err := e.Batch(ctx, r, []Item{
		{Resource: "a", IfMatch: heads["a"], Steps: []Step{{Patches: []any{map[string]any{"op": "replace", "path": "/n", "value": 1.0}}}}},
		{Resource: "z", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}},
	}, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	if !woken(wa, 5*time.Second) {
		t.Fatal("a batch naming a didn't wake its waiter")
	}
	settle()
	if !isOpen(wb) || !isOpen(wc) {
		t.Fatal("a batch woke the waiter of a resource it doesn't name")
	}

	// A write to b wakes b's.
	if _, err := put(e, "n", "b", heads["b"], 1); err != nil {
		t.Fatal(err)
	}
	if !woken(wb, 5*time.Second) {
		t.Fatal("a write to b didn't wake its waiter")
	}
	settle()
	if !isOpen(wc) {
		t.Fatal("a write to b woke c's waiter")
	}

	// A purge of c wakes c's.
	if _, err := e.Purge(ctx, r, "c", heads["c"], true); err != nil {
		t.Fatal(err)
	}
	if !woken(wc, 5*time.Second) {
		t.Fatal("a purge of c didn't wake its waiter")
	}

	// A configuration change wakes every resource waiter of the namespace,
	// of resources that exist or not.
	ws := []<-chan struct{}{e.WaitResource("n", "a"), e.WaitResource("n", "other"), e.WaitResource("n", "nonesuch")}
	other := e.WaitResource("m", "a")
	mkNS(t, e, "m", map[string]any{"read": "public"})
	settle()
	if !woken(other, 5*time.Second) {
		t.Fatal("creating namespace m didn't wake its waiters")
	}
	for i, w := range ws {
		if !isOpen(w) {
			t.Fatalf("waiter %d of n woken by m's configuration", i)
		}
	}
	if _, err := e.WriteConfig(ctx, r, ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "add", "path": "/x-description", "value": "changed"}}}); err != nil {
		t.Fatal(err)
	}
	for i, w := range ws {
		if !woken(w, 5*time.Second) {
			t.Fatalf("waiter %d not woken by a configuration change", i)
		}
	}
}

// The hub drops what it no longer waits on, and wakes what publish names.
func TestHubPublish(t *testing.T) {
	h := newHub()
	ns := h.wait("n")
	a, b := h.waitResource("n", "a"), h.waitResource("n", "b")
	if h.waitResource("n", "a") != a {
		t.Fatal("two waiters of a resource on different channels")
	}
	h.publish("n", []string{"a", "q"}, false)
	if isOpen(ns) || isOpen(a) || !isOpen(b) {
		t.Fatal("publish of a")
	}
	h.publish("n", nil, true)
	if isOpen(b) {
		t.Fatal("publish of the whole namespace left b's waiter")
	}
	if len(h.m) != 0 {
		t.Fatalf("hub kept %v", h.m)
	}
	for i := range 3 {
		h.waitResource("n", fmt.Sprint(i))
	}
	h.publish("other", nil, true)
	if len(h.m["n"].res) != 3 {
		t.Fatal("another namespace's publish woke n's waiters")
	}
}
