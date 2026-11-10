package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// xrev2-leaks, target 6: the snapshot-mirroring path binds A's snapshot to
// the resource too (pl.name), not only the namespace and revision: one
// sealed for another resource of the same namespace at the same id is a
// creation 502, nothing kept. Control: A's own snapshot is mirrored.
func TestV081XLRemoteSnapshotOtherResource(t *testing.T) {
	t.Parallel()
	s, x2, _, snap := newV081Pruned(t)
	otherName, _ := seal.SealSnapshot(s.k1, "m#1", "m", "y", x2, map[string]any{"v": 2.0})
	for name, body := range map[string]string{"own": snap, "another resource's": otherName} {
		t.Run(name, func(t *testing.T) {
			tg, _ := url.Parse(s.a.srv.URL)
			rp := httputil.NewSingleHostReverseProxy(tg)
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && r.URL.Path == "/r/m/x/rev/"+x2 {
					w.Header().Set("Content-Type", seal.ContentType)
					w.Write([]byte(body))
					return
				}
				rp.ServeHTTP(w, r)
			}))
			t.Cleanup(front.Close)
			b := newV081B(t, s, front.URL)
			kB := newKey("badmin")
			r := b.mkRemote("r", remoteGenesis("m", s.at, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}})))
			if name == "own" {
				if r.Code != 201 && r.Code != 200 {
					t.Fatalf("control: %d %s", r.Code, r.Body)
				}
				return
			}
			expectCode(t, r, 502, "upstream")
		})
	}
}

// xrev2-leaks, target 6 (TestV0261PendingBackoff's rule, no hammering):
// once the snapshot is mirrored at creation, B's syncs don't ask A for it
// again, even while A answers 502 for a later revision.
func TestV081XLRemoteSnapshotNotAskedAtSync(t *testing.T) {
	t.Parallel()
	s, x2, x3, _ := newV081Pruned(t)
	p := newV077Proxy(t, s.a, nil)
	b := newV081B(t, s, p.srv.URL)
	_, g := v081Remote(t, b, s, "r")
	before := p.count("GET /r/m/x/rev/"+x2) + p.count("GET /r/m/x/rev/"+x3)
	p.set(map[string]v077Answer{"GET /r/m/x/rev/" + x3: {100, 502, `{"code":"upstream"}`}})
	for range 5 {
		if err := b.e.SyncRemotes(context.Background()); err != nil {
			t.Logf("sync: %v", err)
		}
		_ = b.get("/r/r/x/rev/"+x3, g)
	}
	if after := p.count("GET /r/m/x/rev/"+x2) + p.count("GET /r/m/x/rev/"+x3); after != before {
		t.Fatalf("B asked A %d times across syncs and reads", after-before)
	}
}
