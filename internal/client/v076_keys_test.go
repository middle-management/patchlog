package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/seal"
)

// keysAnswering answers POST /ns/{ns}/keys with status while it is set,
// as a core whose /keys fails or refuses would.
type keysAnswering struct {
	status atomic.Int32
	rt     http.RoundTripper
}

func (f *keysAnswering) RoundTrip(r *http.Request) (*http.Response, error) {
	if st := f.status.Load(); st != 0 && r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/keys") {
		if r.Body != nil {
			r.Body.Close()
		}
		return &http.Response{StatusCode: int(st), Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"code":"injected","message":"injected"}`)), Request: r}, nil
	}
	return f.rt.RoundTrip(r)
}

// TestV076KeysNoRecipientLacking (ENC-5, FSVC-13; §A.4, §E.2.6 Getting
// keys; changelog v0.76 "a wrapped key no recipient key opens is
// lacking, not 503 behind"): a key /keys gives wrapped to the grant's
// enc, with no recipient key configured (NewKeys(nil)), is ErrNoKeys, so
// follow.LacksKey counts it as lacking. Before v0.76 it was a plain
// error, retried as a failure for now.
func TestV076KeysNoRecipientLacking(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	k := clienttest.NewKey("k")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "s")))
	must(op.CreateNamespace(ctx, "s", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"s"}, []string{"create", "read"})))
	a := must(w.Create(ctx, "s", "a", nonced(client.GenesisPatches(map[string]any{"v": "a"}))))
	jwk, _, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	g := k.Grant(t, s.Now(), "user:r", []string{"s"}, []string{"read"}, map[string]any{"enc": jwk})
	noPriv := s.Client(t, client.WithBearer(g), client.WithKeys(client.NewKeys(nil)))
	_, err = noPriv.Doc(ctx, "s", "a", a.ID)
	if !errors.Is(err, client.ErrNoKeys) || !follow.LacksKey(ctx, err) {
		t.Fatalf("a wrapped key without a recipient key: %v (ErrNoKeys %v, LacksKey %v), want lacking",
			err, errors.Is(err, client.ErrNoKeys), follow.LacksKey(ctx, err))
	}
	if errors.Is(err, client.ErrKeyFetch) {
		t.Errorf("a wrapped key /keys gave is no failed fetch: %v", err)
	}
}

// TestV076KeysFetchFailure (FSVC-8; §A.4 Private namespaces, §12.1,
// scenario 100): a failure to fetch a key from /keys wraps ErrKeyFetch
// around /keys' own answer, which still tells a key that can't be had
// for now (a 5xx, a 429) from one lacking for good (a 4xx other than
// 429): a service answers the first 503 behind, the second as lacking.
func TestV076KeysFetchFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	k := clienttest.NewKey("k")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "s")))
	must(op.CreateNamespace(ctx, "s", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"s"}, []string{"create", "read"})))
	a := must(w.Create(ctx, "s", "a", nonced(client.GenesisPatches(map[string]any{"v": "a"}))))
	fk := &keysAnswering{rt: http.DefaultTransport}
	for _, c := range []struct {
		status  int32
		lacking bool
	}{{503, false}, {429, false}, {403, true}, {404, true}} {
		fk.status.Store(c.status)
		// A fresh cache each time: a key once fetched is never fetched
		// again.
		r := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:r", []string{"s"}, []string{"read"})),
			client.WithKeys(client.NewKeys(nil)), client.WithHTTPClient(&http.Client{Transport: fk}))
		_, err := r.Doc(ctx, "s", "a", a.ID)
		ae, ok := client.AsAPIError(err)
		if !errors.Is(err, client.ErrKeyFetch) || !ok || ae.Status != int(c.status) {
			t.Errorf("/keys %d: %v, want ErrKeyFetch around the %d", c.status, err, c.status)
			continue
		}
		if got := follow.LacksKey(ctx, err); got != c.lacking {
			t.Errorf("/keys %d: LacksKey %v, want %v", c.status, got, c.lacking)
		}
	}
	fk.status.Store(0)
	r := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:r", []string{"s"}, []string{"read"})),
		client.WithKeys(client.NewKeys(nil)), client.WithHTTPClient(&http.Client{Transport: fk}))
	if d := must(r.Doc(ctx, "s", "a", a.ID)); d.Value.(map[string]any)["v"] != "a" {
		t.Fatalf("doc %s", d.Raw)
	}
}
