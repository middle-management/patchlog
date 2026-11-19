package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// countReads counts resource log transactions until the test ends.
func countReads(t *testing.T) *atomic.Int64 {
	var n atomic.Int64
	testResourceLogRead = func() { n.Add(1) }
	t.Cleanup(func() { testResourceLogRead = nil })
	return &n
}

// liveAt asks a resource long-poll's read from since and checks how many
// transactions it took and how many entries it got; it returns the next
// since.
func liveAt(t *testing.T, e *Engine, reads *atomic.Int64, cred Credentials, name, since string, wantReads int64, wantEntries int) string {
	t.Helper()
	before := reads.Load()
	lg, err := e.ResourceLiveLog(context.Background(), "n", name, since, 1000, cred)
	if err != nil {
		t.Fatalf("%s since %q: %v", name, since, err)
	}
	if n := reads.Load() - before; n != wantReads || lg.Status != 200 || len(lg.Entries) != wantEntries {
		t.Fatalf("%s since %q: status %d, %d entries, %d reads; want 200, %d entries, %d reads", name, since, lg.Status, len(lg.Entries), n, wantEntries, wantReads)
	}
	return lg.Last
}

// A resource long-poll from its quiet resource's head is answered without
// a transaction (live.go, quiet resources) until a commit names the
// resource, or concerns the whole namespace, or changes what reads may
// return; writes to other resources don't end it.
func TestQuietResource(t *testing.T) {
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	cfg := mkNS(t, e, "n", map[string]any{"read": "public"})
	a, err := put(e, "n", "a", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := put(e, "n", "other", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	settle(t, e)
	reads := countReads(t)
	anyone := Credentials{}

	head := liveAt(t, e, reads, anyone, "a", "", 1, 1)
	if head != a {
		t.Fatalf("head %s, want %s", head, a)
	}
	hits := e.liveQuiet.Load()
	for range 5 {
		liveAt(t, e, reads, anyone, "a", head, 0, 0)
	}
	if n := e.liveQuiet.Load() - hits; n != 5 {
		t.Fatalf("%d quiet answers, want 5", n)
	}
	// Any credentials, in a public namespace.
	liveAt(t, e, reads, Credentials{Bearer: "anything"}, "a", head, 0, 0)

	// Writes to another resource leave a quiet.
	for i := 1; i <= 10; i++ {
		if other, err = put(e, "n", "other", other, i); err != nil {
			t.Fatal(err)
		}
	}
	settle(t, e)
	liveAt(t, e, reads, anyone, "a", head, 0, 0)

	// A since that isn't the head is read.
	liveAt(t, e, reads, anyone, "a", "", 1, 1)

	// A write to a is read, and its head is quiet in turn.
	if a, err = put(e, "n", "a", a, 1); err != nil {
		t.Fatal(err)
	}
	settle(t, e)
	head = liveAt(t, e, reads, anyone, "a", head, 1, 1)
	if head != a {
		t.Fatalf("head %s after a write, want %s", head, a)
	}
	liveAt(t, e, reads, anyone, "a", head, 0, 0)

	// A configuration change ends every quiet resource of the namespace.
	if _, err := e.WriteConfig(ctx, Request{NS: "n", Cred: who.Cred}, ConfigChange{IfMatch: cfg,
		Patches: []any{map[string]any{"op": "add", "path": "/x-description", "value": "changed"}}}); err != nil {
		t.Fatal(err)
	}
	settle(t, e)
	liveAt(t, e, reads, anyone, "a", head, 1, 0)
	liveAt(t, e, reads, anyone, "a", head, 0, 0)

	// A purge is read: the resource is gone.
	r := who
	r.NS = "n"
	if _, err := e.Purge(ctx, r, "a", head, true); err != nil {
		t.Fatal(err)
	}
	settle(t, e)
	before := reads.Load()
	lg, err := e.ResourceLiveLog(ctx, "n", "a", head, 1000, anyone)
	if err != nil || lg.Status != 410 || reads.Load()-before != 1 {
		t.Fatalf("after a purge: %+v %v, %d reads", lg, err, reads.Load()-before)
	}
}

// In a namespace that isn't public a quiet resource is kept per bearer
// grant, and stands only while the grant's read check would pass:
// revocation, expiry and a grant that can't read the resource each send
// the request to the database.
func TestQuietResourceGrants(t *testing.T) {
	ctx := context.Background()
	reader := func() map[string]any {
		return map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"n"}, "can": []any{"read"}}
	}
	t.Run("per grant", func(t *testing.T) {
		var clock atomic.Int64
		e, mint, _ := authEngine(t, &clock)
		admin := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"n"}, "can": []any{"read", "create", "append", "config"}})}
		if _, err := e.WriteResource(ctx, Request{NS: "n", Cred: admin}, Item{Resource: "a", IfNoneMatch: true,
			Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 0.0}}}}}}); err != nil {
			t.Fatal(err)
		}
		reads := countReads(t)
		r1, r2 := Credentials{Bearer: mint(reader())}, Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:s", "ns": []any{"n"}, "can": []any{"read"}})}
		head := liveAt(t, e, reads, r1, "a", "", 1, 1)
		liveAt(t, e, reads, r1, "a", head, 0, 0)
		liveAt(t, e, reads, r2, "a", head, 1, 0)
		liveAt(t, e, reads, r2, "a", head, 0, 0)
		// Without a grant, or with an edge grant, nothing is answered from
		// another's read.
		if lg, err := e.ResourceLiveLog(ctx, "n", "a", head, 1000, Credentials{}); status(err) != 401 {
			t.Fatalf("no grant: %+v %v, want 401", lg, err)
		}
		if _, own := quietKeys("n", "a", Credentials{Bearer: r1.Bearer, Edge: &EdgeGrant{}}); own != "" {
			t.Fatal("an edge grant is keyed by its bearer")
		}
		// A grant that can't read a is refused every time (as unknown).
		other := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:o", "ns": []any{"n"}, "can": []any{"read"},
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "b"}}})}
		for range 2 {
			before := reads.Load()
			if _, err := e.ResourceLiveLog(ctx, "n", "a", head, 1000, other); status(err) != 404 || reads.Load()-before != 1 {
				t.Fatalf("a grant for b only: %v, %d reads", err, reads.Load()-before)
			}
		}
	})
	t.Run("revoked", func(t *testing.T) {
		var clock atomic.Int64
		e, admin, rd, cfg, _, _ := liveEngine(t, &clock, reader())
		reads := countReads(t)
		head := liveAt(t, e, reads, rd, "a", "", 1, 1)
		liveAt(t, e, reads, rd, "a", head, 0, 0)
		g, err := grant.Decode(rd.Bearer, 0)
		if err != nil {
			t.Fatal(err)
		}
		gen := e.rc.nsGen("n").Load()
		if _, err := e.WriteConfig(ctx, Request{NS: "n", Cred: admin}, ConfigChange{IfMatch: cfg,
			Patches: []any{map[string]any{"op": "add", "path": "/revoked", "value": []any{g.RevocationIDs()[0]}}}}); err != nil {
			t.Fatal(err)
		}
		tailed(t, e, "n", gen)
		if _, err := e.ResourceLiveLog(ctx, "n", "a", head, 1000, rd); status(err) != 401 {
			t.Fatalf("a revoked grant: %v, want 401", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		var clock atomic.Int64
		clock.Store(time.Now().UnixMilli())
		r := reader()
		r["exp"] = time.UnixMilli(clock.Load()).Add(time.Minute).UTC().Format(time.RFC3339)
		e, _, rd, _, _, _ := liveEngine(t, &clock, r)
		reads := countReads(t)
		head := liveAt(t, e, reads, rd, "a", "", 1, 1)
		liveAt(t, e, reads, rd, "a", head, 0, 0)
		clock.Add(2 * time.Minute.Milliseconds())
		if _, err := e.ResourceLiveLog(ctx, "n", "a", head, 1000, rd); status(err) != 401 {
			t.Fatalf("an expired grant: %v, want 401", err)
		}
	})
}

// On Postgres, a write on another instance ends this instance's quiet
// resource once its tailer sees the write: the next long-poll is read and
// gets the write.
func TestPGQuietResourceOtherInstance(t *testing.T) {
	a, b := twoInstances(t)
	mkNS(t, a, "n", map[string]any{"read": "public"})
	r, err := put(a, "n", "r", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	settle(t, b)
	reads := countReads(t)
	head := liveAt(t, b, reads, Credentials{}, "r", "", 1, 1)
	liveAt(t, b, reads, Credentials{}, "r", head, 0, 0)
	if r, err = put(a, "n", "r", r, 1); err != nil {
		t.Fatal(err)
	}
	settle(t, b)
	if next := liveAt(t, b, reads, Credentials{}, "r", head, 1, 1); next != r {
		t.Fatalf("head %s after the other instance's write, want %s", next, r)
	}
}
