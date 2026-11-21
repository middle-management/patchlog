package dav_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
)

// v88RT is an http.RoundTripper of a function.
type v88RT func(*http.Request) (*http.Response, error)

func (f v88RT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// v0.88 TOOLS §H.4 Answers ("a write or a due re-check of the user's
// grant (§H.7) included"): a re-check of alice's grant that falls due
// with her request and finds the core unable to answer (503) fails that
// request, 503 with the gateway's own Retry-After, carrying nothing of
// the core's answer; once the core answers again, her request is served.
func TestGatewayDueRecheckCounts(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	k := clienttest.NewKey("k")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
	must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	admin := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"docs"}, []string{"read", "create", "append", "config"})))
	var down atomic.Bool
	rt := v88RT(func(r *http.Request) (*http.Response, error) {
		if down.Load() && strings.HasSuffix(r.URL.Path, "/principal") {
			body := `{"code":"busy","message":"the core's own words"}`
			return &http.Response{StatusCode: 503, Header: http.Header{"Content-Type": {"application/json"}, "Retry-After": {"77"}},
				Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: r}, nil
		}
		return http.DefaultTransport.RoundTrip(r)
	})
	srv := must(dav.New(dav.Options{Client: s.Client(t, client.WithHTTPClient(&http.Client{Transport: rt})), Namespaces: []string{"docs"},
		Gateway: true, Logf: t.Logf, Now: clock, VerifyEvery: time.Minute}))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	e := &env{t: t, ctx: ctx, s: s, c: admin, dav: hs}
	alice := k.Grant(t, s.Now(), "user:alice", []string{"docs"}, []string{"read"})
	e.expect(e.doAs(alice, "PUT", "/docs/.swp", "alice"), 201, "alice's scratch")
	down.Store(true)
	// Not due: answered without asking.
	e.expect(e.doAs(alice, "GET", "/docs/.swp", ""), 200, "alice, her grant checked a moment ago")
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	r := e.doAs(alice, "GET", "/docs/.swp", "")
	if r.status != 503 || r.header.Get("Retry-After") == "" || r.header.Get("Retry-After") == "77" || strings.Contains(r.body, "the core's own words") {
		t.Fatalf("alice's request with her grant's re-check due and the core busy: %d %v %s, want 503 with the gateway's own Retry-After", r.status, r.header, r.body)
	}
	down.Store(false)
	e.expect(e.doAs(alice, "GET", "/docs/.swp", ""), 200, "alice, once the core answers")
}
