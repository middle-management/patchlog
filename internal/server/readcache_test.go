package server

import (
	"sync"
	"testing"
	"time"
)

// Transaction-free reads of public namespaces (core/readcache.go) never
// serve an answer a later commit changed: appends move the head, deletes
// tombstone it, and purges, prunes and namespace purges take revisions
// away, each seen by the very next read after having been cached.
func TestReadCacheInvalidation(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, withArchive(t, dir), withoutRetentionLoop)
	e.mkNS("pub", map[string]any{"read": "public"})
	revs := e.chain("pub", "a", 4)
	head := func(ns, name string) string {
		t.Helper()
		r := e.get("/r/" + ns + "/" + name)
		if r.Code != 302 {
			return ""
		}
		return r.H.Get("ETag")
	}
	warm := func(path string, code int) {
		t.Helper()
		for i := 0; i < 2; i++ {
			expect(t, e.get(path), code)
		}
	}

	// Heads follow appends and deletes.
	if h := head("pub", "a"); h != `"`+revs[3]+`"` {
		t.Fatalf("head %s, want %s", h, revs[3])
	}
	r5 := e.appendRev("pub", "a", revs[3], ops(op("replace", "/n", 9.0)))
	if h := head("pub", "a"); h != `"`+r5+`"` {
		t.Fatalf("head after append %s, want %s", h, r5)
	}
	e.create("pub", "b", map[string]any{"x": 1.0})
	bHead := head("pub", "b")
	e.del("pub", "b", bHead[1:len(bHead)-1])
	if r := e.get("/r/pub/b"); r.Code == 302 && r.H.Get("ETag") == bHead {
		t.Fatalf("head of a deleted resource still %s", bHead)
	}

	// Pruning takes cached revisions below the horizon away.
	warm("/r/pub/a/rev/"+revs[1], 200)
	e.clock.Advance(time.Hour)
	expect(t, e.prune("pub", "a", map[string]any{"horizon": revs[3]}, "admin"), 200)
	expectCode(t, e.get("/r/pub/a/rev/"+revs[1]), 410, "pruned")

	// A resource purge.
	warm("/r/pub/a/rev/"+revs[3], 200)
	expect(t, e.purge("pub", "a", r5, "admin"), 204)
	expect(t, e.get("/r/pub/a/rev/"+revs[3]), 410)
	expect(t, e.get("/r/pub/a"), 410)

	// A namespace purge.
	c := e.create("pub", "c", map[string]any{"y": 1.0})
	warm("/r/pub/c/rev/"+c, 200)
	warm("/r/pub/c", 302)
	expect(t, e.patchNS("pub", ops(op("add", "/frozen", true)), ""), 201)
	warm("/r/pub/c/rev/"+c, 200)
	warm("/r/pub/c", 302)
	expect(t, e.do(req{method: "POST", path: "/ns/pub/purge", ifMatch: e.nsHead("pub"), author: "admin"}), 204)
	expect(t, e.get("/r/pub/c/rev/"+c), 410)
	if r := e.get("/r/pub/c"); r.Code == 302 {
		t.Fatalf("head of a purged namespace: 302 %s", r.H.Get("Location"))
	}
}

// Making a public namespace private stops anonymous reads at once, cached or
// not.
func TestReadCachePublicToPrivate(t *testing.T) {
	f := newAuthFixture(t, map[string]any{})
	e := f.tenv
	expect(t, e.patchNS("sec", ops(op("replace", "/read", "public")), f.adminG), 201)
	id := e.create("sec", "doc", map[string]any{"t": "x"}, f.adminG)
	for i := 0; i < 2; i++ {
		expect(t, e.get("/r/sec/doc/rev/"+id), 200)
		expect(t, e.get("/r/sec/doc"), 302)
	}
	expect(t, e.patchNS("sec", ops(op("replace", "/read", "grant")), f.adminG), 201)
	expect(t, e.get("/r/sec/doc/rev/"+id), 401)
	expect(t, e.get("/r/sec/doc"), 401)
	expect(t, e.get("/r/sec/doc/rev/"+id, f.adminG), 200)
}

// Concurrent readers and a writer: every head a reader sees is one the
// writer had produced by the time the read returned, and reads after the
// last write see the last head.
func TestReadCacheConcurrentHeads(t *testing.T) {
	e := newEnv(t, withFileDB(t))
	e.mkNS("pub", map[string]any{"read": "public"})
	ids := []string{e.create("pub", "a", map[string]any{"n": 0.0})}
	var mu sync.Mutex
	written := map[string]bool{`"` + ids[0] + `"`: true}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r := e.get("/r/pub/a")
				mu.Lock()
				ok := written[r.H.Get("ETag")]
				mu.Unlock()
				if r.Code != 302 || !ok {
					t.Errorf("read %d %q, not a written head", r.Code, r.H.Get("ETag"))
					return
				}
			}
		}()
	}
	for i := 1; i < 60; i++ {
		// Record the id before it can be read: its ETag is known only after
		// the write returns, so the write happens under the lock.
		e.clock.Advance(time.Second)
		mu.Lock()
		id := e.appendRev("pub", "a", ids[len(ids)-1], ops(op("replace", "/n", float64(i))))
		ids = append(ids, id)
		written[`"`+id+`"`] = true
		mu.Unlock()
	}
	close(stop)
	wg.Wait()
	last := `"` + ids[len(ids)-1] + `"`
	if h := e.get("/r/pub/a").H.Get("ETag"); h != last {
		t.Fatalf("after the last write: head %s, want %s", h, last)
	}
}

// §9: a non-live log range's unknown resource 404 is "short", its purged
// 410 "long"; an unknown id of GET /ns/{ns}/rev/{id} and /heads is "short"
// for the namespace's visibility, public or at the edge.
func TestReviewLogCacheClasses(t *testing.T) {
	e := newEnv(t)
	e.mkNS("pub", map[string]any{"read": "public"})
	e.mkNS("priv", map[string]any{})
	e.create("pub", "a", map[string]any{"v": 1.0}, "alice")

	r := e.get("/r/pub/nope/log")
	expectCode(t, r, 404, "not_found")
	if cc := r.H.Get("Cache-Control"); cc != "public, max-age=5" {
		t.Fatalf("unknown resource's log: %q", cc)
	}
	expect(t, e.purge("pub", "a", e.head("pub", "a"), "admin"), 204)
	r = e.get("/r/pub/a/log")
	expectCode(t, r, 410, "gone")
	if cc := r.H.Get("Cache-Control"); cc != "public, max-age=86400, s-maxage=31536000" {
		t.Fatalf("purged resource's log: %q", cc)
	}

	for _, ns := range []string{"pub", "priv"} {
		want := "public, max-age=5"
		if ns == "priv" {
			want = "private, max-age=5"
		}
		for _, path := range []string{"/ns/" + ns + "/rev/2bbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "/ns/" + ns + "/rev/2bbbbbbbbbbbbbbbbbbbbbbbbbbbbb/heads"} {
			r := e.get(path)
			expectCode(t, r, 404, "not_found")
			if cc := r.H.Get("Cache-Control"); cc != want {
				t.Fatalf("%s: %q, want %q", path, cc, want)
			}
		}
	}
}
