package tree_test

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// A listing is 503 behind until the service holds a checkpoint of every
// namespace it follows: the catalog, and each namespace the catalog
// trusts, which a service started with a fresh database (or trusting it
// lately) catches up with after the catalog. Meanwhile every placement of
// an item there would be missing (§B.3), and a folder shown empty that
// isn't, which a sync tool mirrors as deleted files (§H.3). A trusted
// namespace the service can't follow (one that doesn't exist) isn't
// waited for.
func TestListingsWaitForTrusted(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed(t)
	var hold atomic.Bool
	hold.Store(true)
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		for hold.Load() && strings.HasPrefix(req.URL.Path, "/ns/matches/") && (strings.Contains(req.URL.Path, "/log") || strings.HasSuffix(req.URL.Path, "/events") || strings.Contains(req.URL.Path, "/heads")) {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(5 * time.Millisecond):
			}
		}
		return base.RoundTrip(req)
	})
	core := w.s.Client(t, client.WithAuthor("tree"), client.WithHTTPClient(&http.Client{Transport: rt}))
	x := startSvc(t, core, svcOpts{})
	t.Cleanup(func() { hold.Store(false) })
	x.caughtUp("cat")
	r := x.raw("/cat/children?of=season", "")
	for r.status == http.StatusFound {
		r = x.raw(r.header.Get("Location"), "")
	}
	if r.status != http.StatusServiceUnavailable || r.body["code"] != "behind" || !strings.Contains(r.body["message"].(string), "matches") || r.header.Get("Retry-After") == "" {
		t.Fatalf("a listing before matches has a checkpoint: %d %v %v", r.status, r.header, r.body)
	}
	hold.Store(false)
	x.caughtUp("matches")
	if got := names(x.get("/cat/children?of=season", "")["children"]); got != "matches.opener,matches.derby" {
		t.Fatalf("once caught up: %s", got)
	}

	// Trusting a namespace that doesn't exist: listings don't wait for it.
	ctx := context.Background()
	h := must(w.c.NSHead(ctx, "cat"))
	must(w.c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/catalog/trust/-", "value": "nosuch"}}))
	x.caughtUp("cat")
	waitFor(t, "a listing while nosuch can't be followed", func() bool {
		r := x.raw("/cat/children?of=season", "")
		return r.status == http.StatusFound || r.status == http.StatusOK
	})
}

// roundTrip adapts a function to http.RoundTripper.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
