package index

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
)

// TestFSForgetRace (§A.1: a purge must drop kept results): a request that
// reads a namespace's state from the origin before a purge in it commits,
// and stores what it read in fstate after the purge dropped fstate's state
// of that namespace (fsForget), must not keep it: it would outlive the
// purge until its cache key changed. That holds for a namespace the index
// serves and for a member namespace it follows only for visibility, whose
// purges both drop fstate's state through fsForget (purgeStored). Each
// case pauses a fill between its origin read and its store (beforeStore),
// runs the purge there, and checks what the fill left behind; a fill with
// no purge, or a purge of another namespace, still stores.
func TestFSForgetRace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/heads") {
			http.NotFound(w, r) // a tombstone's log: its last live document is gone
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"heads":[]}`))
	}))
	defer srv.Close()
	c, err := client.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	id := ids.Of([]byte("x")).String()
	tomb := ids.Of([]byte("tombstone")).String()
	cat := fsCat{ns: "cat", id: id, doc: map[string]any{"catalog": map[string]any{"trust": []any{"mem"}}}}
	catIDs := map[string]string{"cat": id, "mem": id}
	catKey := "cat\x00" + id + "\x00mem\x00" + id

	type fill struct {
		run    func(ctx context.Context, ix *Index) error
		pause  string                          // the store to pause before (beforeStore)
		stored func(ix *Index) map[string]bool // what is kept, by store
	}
	live := func(ns string) fill {
		return fill{
			run: func(ctx context.Context, ix *Index) error {
				_, err := ix.liveAt(ctx, ns, id)
				return err
			},
			pause: "live",
			stored: func(ix *Index) map[string]bool {
				_, ok := ix.fs.live.Get(ns + "\x00" + id)
				return map[string]bool{"live": ok}
			},
		}
	}
	catalog := func(pause string) fill {
		return fill{
			run: func(ctx context.Context, ix *Index) error {
				_, err := ix.catalogAt(ctx, cat, catIDs)
				return err
			},
			pause: pause,
			stored: func(ix *Index) map[string]bool {
				_, cats := ix.fs.cats.Get(catKey)
				_, nodes := ix.fs.nodes["cat"]
				return map[string]bool{"cat": cats, "nodes": nodes}
			},
		}
	}
	lastLive := fill{
		run: func(ctx context.Context, ix *Index) error {
			_, err := ix.lastLive(ctx, "cat", "node1", tomb)
			return err
		},
		pause: "deleted",
		stored: func(ix *Index) map[string]bool {
			_, ok := ix.fs.deleted.Get("cat\x00node1\x00" + tomb)
			return map[string]bool{"deleted": ok}
		},
	}

	for _, tc := range []struct {
		name  string
		fill  fill
		purge string // the namespace purged while the fill pauses; "" none
		want  map[string]bool
	}{
		{"live/no purge", live("srv"), "", map[string]bool{"live": true}},
		{"live/other purged", live("srv"), "other", map[string]bool{"live": true}},
		{"live/served purged", live("srv"), "srv", map[string]bool{"live": false}},
		{"live/member purged", live("mem"), "mem", map[string]bool{"live": false}},
		{"catalog/no purge", catalog("cat"), "", map[string]bool{"cat": true, "nodes": true}},
		{"catalog/member purged", catalog("cat"), "mem", map[string]bool{"cat": false, "nodes": true}},
		{"catalog/catalog purged before its graph is kept", catalog("nodes"), "cat", map[string]bool{"cat": false, "nodes": false}},
		{"catalog/catalog purged before it is kept", catalog("cat"), "cat", map[string]bool{"cat": false, "nodes": false}},
		{"lastLive/no purge", lastLive, "", map[string]bool{"deleted": true}},
		{"lastLive/catalog purged", lastLive, "cat", map[string]bool{"deleted": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix := openBare(t, filepath.Join(t.TempDir(), "i.db"))
			ix.c = c
			ix.fs.init()
			ix.fs.docs.Put("mem\x00"+id, map[string]any{}, 1) // docAt of the member, which no purge drops
			paused, resume := make(chan struct{}), make(chan struct{})
			ix.fs.beforeStore = func(what string) {
				if what == tc.fill.pause {
					close(paused)
					<-resume
				}
			}
			done := make(chan error, 1)
			go func() { done <- tc.fill.run(context.Background(), ix) }()
			select {
			case <-paused:
			case err := <-done:
				t.Fatalf("the fill ended without storing %s: %v", tc.fill.pause, err)
			}
			// The fill has read the origin, before the purge committed;
			// the purge drops fstate's state now, before the fill stores.
			if tc.purge != "" {
				ix.fsForget(tc.purge)
			}
			close(resume)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			got := tc.fill.stored(ix)
			for what, want := range tc.want {
				if got[what] != want {
					t.Errorf("%s kept: %v, want %v", what, got[what], want)
				}
			}
		})
	}
}
