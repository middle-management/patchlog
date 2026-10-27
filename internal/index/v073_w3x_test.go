package index_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// W3X (P29 ENC-38 x the index; §A.4, §E.2.6, §12.1): a namespace the index
// follows is raised from none to e2e (allowed since P29), and the index
// has no keyring recipient key, so it lacks the namespace's keys as
// configured. Running through the raise, it skips the namespace and stops
// following it, as it does when it starts: queries answer 404 not_found,
// not 503 behind forever. Other namespaces are served as before, and a
// restart answers the same.
func TestW3XIndexRaisedToE2EWhileFollowed(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, KeyStore: keyStore(t)})
	c := s.Client(t, client.WithAuthor("admin"))
	for _, ns := range []string{"r", "p"} {
		must(c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}))
		must(c.CreateDoc(ctx, ns, "a", map[string]any{"title": "zebra"}))
	}
	db := filepath.Join(t.TempDir(), "i.db")
	x := startSvc(t, c, svcOpts{db: db, ns: []string{"r", "p"}, untyped: true})
	x.caughtUp("r")
	x.caughtUp("p")
	if r := x.search("/r", ""); len(resources(r)) != 1 {
		t.Fatalf("before the raise: %v", r)
	}
	h := must(c.NSHead(ctx, "r"))
	must(c.PatchConfig(ctx, "r", h.Config, []any{map[string]any{"op": "add", "path": "/encryption",
		"value": map[string]any{"level": "e2e", "epoch": 1}}}))
	follow := func(y *svc, path string) resp {
		r := y.raw(path, "")
		for r.status == 302 {
			r = y.raw(r.header.Get("Location"), "")
		}
		return r
	}
	// Behind at most while the config entry is being applied, then 404
	// for good.
	waitFor(t, "404 for the raised namespace", func() bool { return follow(x, "/r").status == 404 })
	for i := 0; i < 20; i++ {
		if r := follow(x, "/r"); r.status != 404 {
			t.Fatalf("running through the raise: %d %v (Retry-After %q), want 404 as after a restart", r.status, r.body, r.header.Get("Retry-After"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := x.raw("/_status", "").body["namespaces"].([]any); st[1].(map[string]any)["skipped"] != true {
		t.Errorf("status of r after the raise: %v", st)
	}
	must(c.CreateDoc(ctx, "p", "b", map[string]any{"title": "zebra"}))
	x.caughtUp("p")
	if r := x.search("/p", ""); len(resources(r)) != 2 {
		t.Errorf("another namespace after r is skipped: %v", r)
	}
	x.stop()
	y := startSvc(t, c, svcOpts{db: db, ns: []string{"r", "p"}, untyped: true})
	waitFor(t, "skip after restart", func() bool {
		return y.raw("/_status", "").body["namespaces"].([]any)[1].(map[string]any)["skipped"] == true
	})
	if r := follow(y, "/r"); r.status != 404 {
		t.Fatalf("restarted: %d %v, want 404", r.status, r.body)
	}
}
