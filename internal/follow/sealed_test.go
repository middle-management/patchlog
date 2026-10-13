package follow_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// A follower works over a sealed namespace (Addendum E.2) when its client
// has keys: namespace logs, long-polls, events and documents decrypt
// transparently.
func TestFollowSealed(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"long-poll", "sse"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			ks, err := keystore.New(keystore.Generate())
			if err != nil {
				t.Fatal(err)
			}
			s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, KeyStore: ks})
			c := s.Client(t, client.WithAuthor("admin"), client.WithKeys(client.NewKeys(nil)))
			must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}))
			nonce := func(p []any) []any {
				return append(p, map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
			}
			a := must(c.Create(ctx, "main", "a", nonce(client.GenesisPatches(map[string]any{"n": 0}))))
			must(c.Append(ctx, "main", "a", a.ID, nonce(rep("/n", 1))))

			cp := &follow.MemoryCheckpoints{}
			rec := &recorder{cp: cp}
			opts := []follow.Option{follow.WithBackoff(time.Millisecond, 10*time.Millisecond)}
			if mode == "sse" {
				opts = append(opts, follow.WithSSE())
			}
			r := start(follow.New(c, "main", cp, rec, opts...))
			waitFor(t, "catch-up", checkpointIs(t, cp, c, "main"))
			if got := rec.kinds("main"); fmt.Sprint(got) != "[config head head]" {
				t.Fatalf("catch-up kinds %v", got)
			}
			first := rec.snapshot()[0].Units[0]
			if enc, _ := first.Config.Value["encryption"].(map[string]any); enc["level"] != "sealed" {
				t.Fatalf("config %+v", first.Config)
			}
			// Live entries, then the documents they point at.
			h := must(c.Head(ctx, "main", "a"))
			w := must(c.Append(ctx, "main", "a", h.ID, nonce(rep("/n", 2))))
			waitFor(t, "live", checkpointIs(t, cp, c, "main"))
			bs := rec.snapshot()
			last := bs[len(bs)-1].Units
			if tg := last[len(last)-1].Entry.Target; tg != w.ID {
				t.Fatalf("live target %s want %s", tg, w.ID)
			}
			if d := must(c.Doc(ctx, "main", "a", w.ID)); d.Value.(map[string]any)["n"] != 2.0 {
				t.Fatalf("doc %s", d.Raw)
			}
			r.stop(t)
		})
	}
}

// A sealed namespace's log, long-polls, events and documents are 410
// purged once it is purged, with head its purge-ns entry (§8.5): a
// follower takes that as the purge, at that head, as for the entry
// itself. Whether it is following when the purge comes, starts from an
// earlier checkpoint, or starts at the purge, it ends with ErrPurged; and
// a purged sealed branch discovered from its branch entry is bootstrapped
// as purged (§10 Branches: discovery).
func TestFollowSealedPurged(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"long-poll", "sse"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			testFollowSealedPurged(t, mode)
		})
	}
}

// purgedRun is a follower run to its end.
type purgedRun struct {
	rec    *recorder
	cp     *follow.MemoryCheckpoints
	mu     sync.Mutex
	purged bool // a purged state was reported
	err    error
	done   chan struct{}
}

func testFollowSealedPurged(t *testing.T, mode string) {
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, KeyStore: ks})
	c := s.Client(t, client.WithAuthor("admin"), client.WithKeys(client.NewKeys(nil)))
	sealed := map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}
	nonce := func(p []any) []any {
		return append(p, map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
	}
	purge := func(ns string) string {
		h := must(c.NSHead(ctx, ns))
		must(c.PatchConfig(ctx, ns, h.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
		return must(c.PurgeNamespace(ctx, ns, must(c.NSHead(ctx, ns)).ID))
	}
	opts := func(extra ...follow.Option) []follow.Option {
		o := append([]follow.Option{follow.WithBackoff(time.Millisecond, 10*time.Millisecond)}, extra...)
		if mode == "sse" {
			o = append(o, follow.WithSSE())
		}
		return o
	}
	run := func(cp *follow.MemoryCheckpoints) *purgedRun {
		r := &purgedRun{rec: &recorder{cp: cp}, cp: cp, done: make(chan struct{})}
		f := follow.New(c, "main", cp, r.rec, opts(follow.WithOnState(func(st follow.State) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.purged = r.purged || st.NS == "main" && st.Purged
		}))...)
		go func() {
			defer close(r.done)
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			r.err = f.Run(cctx)
		}()
		return r
	}
	// ended checks a run ended at the purge: its last unit is the purge-ns
	// at head, its checkpoint is head, and it reported the state.
	ended := func(what string, r *purgedRun, head string) {
		t.Helper()
		<-r.done
		if !errors.Is(r.err, follow.ErrPurged) {
			t.Fatalf("%s: Run: %v", what, r.err)
		}
		bs := r.rec.snapshot()
		if len(bs) == 0 {
			t.Fatalf("%s: nothing delivered", what)
		}
		last := bs[len(bs)-1]
		u := last.Units[len(last.Units)-1]
		if u.Entry.Kind != "purge-ns" || u.Entry.ID != head || last.NewCheckpoint != head || !last.Coalesce().PurgedNS {
			t.Fatalf("%s: last batch %+v", what, last)
		}
		if got := must(r.cp.Load(ctx, clienttest.Origin, "main")); got != head {
			t.Fatalf("%s: checkpoint %s, want %s", what, got, head)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if !r.purged {
			t.Fatalf("%s: no purged state", what)
		}
	}

	must(c.CreateNamespace(ctx, "main", sealed))
	must(c.Create(ctx, "main", "a", nonce(client.GenesisPatches(map[string]any{"n": 0}))))
	early := must(c.NSHead(ctx, "main")).ID

	// Following when the purge comes: the long-poll or the stream is 410.
	live := run(&follow.MemoryCheckpoints{})
	waitFor(t, "catch-up", checkpointIs(t, live.cp, c, "main"))
	head := purge("main")
	ended("live", live, head)

	// From an earlier checkpoint: the catch-up range is 410.
	cp := &follow.MemoryCheckpoints{}
	cp.Save(clienttest.Origin, "main", early)
	late := run(cp)
	ended("catch-up", late, head)
	if bs := late.rec.snapshot(); len(bs) != 1 || bs[0].From != early || !bs[0].Snapshot || !bs[0].Units[0].Synthetic {
		t.Fatalf("catch-up batches %+v", bs)
	}

	// At the purge already: nothing more is delivered.
	cp = &follow.MemoryCheckpoints{}
	cp.Save(clienttest.Origin, "main", head)
	at := run(cp)
	<-at.done
	if !errors.Is(at.err, follow.ErrPurged) || len(at.rec.snapshot()) != 0 || !at.purged {
		t.Fatalf("at the purge: %v %+v", at.err, at.rec.snapshot())
	}

	// A sealed branch purged before its base's follower reaches its branch
	// entry: bootstrapped as purged, with no listing or log to read.
	must(c.CreateNamespace(ctx, "base", sealed))
	must(c.Create(ctx, "base", "b", nonce(client.GenesisPatches(map[string]any{"n": 0}))))
	must(c.CreateBranch(ctx, "base", client.BranchRequest{Name: "br"}))
	bHead := purge("br")
	bcp := &follow.MemoryCheckpoints{}
	brec := &recorder{cp: bcp}
	r := start(follow.New(c, "base", bcp, brec, opts(follow.WithBranches())...))
	waitFor(t, "branch purge", func() bool {
		got, _ := bcp.Load(ctx, clienttest.Origin, "br")
		return got == bHead
	})
	if k := brec.kinds("br"); fmt.Sprint(k) != "[purge-ns]" {
		t.Fatalf("branch kinds %v", k)
	}
	r.stop(t)
}
