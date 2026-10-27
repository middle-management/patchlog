package derived_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// v073KeysStatus answers POST /ns/{ns}/keys with status from the after-th
// call on.
type v073KeysStatus struct {
	status, after, n int
	rt               http.RoundTripper
}

func (f *v073KeysStatus) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/keys") {
		if f.n++; f.n > f.after {
			return &http.Response{StatusCode: f.status, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{"code":"injected","message":"injected"}`)), Request: r}, nil
		}
	}
	return f.rt.RoundTrip(r)
}

// TestV073SkipLacksKeys (IX-2, §A.4, §E.2.6): Skip tells a namespace
// skipped for want of keys (an e2e one without a recipient key,
// client.ErrNoKeys, a 4xx from /keys), which services answer 404 as one
// they don't follow, from one whose keys can't be fetched for now (a 5xx
// or 429), which they answer 503 behind.
func TestV073SkipLacksKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("admin"), client.WithKeys(client.NewKeys(nil)))
	for ns, lv := range map[string]string{"sec": "sealed", "e": "e2e", "plain": ""} {
		doc := map[string]any{"read": "public"}
		if lv != "" {
			doc["encryption"] = map[string]any{"level": lv}
		}
		if _, err := c.CreateNamespace(ctx, ns, doc); err != nil {
			t.Fatal(err)
		}
	}
	ps := append(client.GenesisPatches(map[string]any{}), map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
	if _, err := c.Create(ctx, "sec", "a", ps); err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		name, ns  string
		status    int // of POST /keys after the first, which reads the namespace document
		reason    bool
		lacksKeys bool
	}{
		{"plain", "plain", 0, false, false},
		{"e2e without a recipient key", "e", 0, true, true},
		{"sealed, /keys 503", "sec", http.StatusServiceUnavailable, true, false},
		{"sealed, /keys 429", "sec", http.StatusTooManyRequests, true, false},
		{"sealed, /keys 403", "sec", http.StatusForbidden, true, true},
	} {
		kc := c
		if x.status != 0 {
			kc = c.With(client.WithHTTPClient(&http.Client{Transport: &v073KeysStatus{status: x.status, after: 1, rt: http.DefaultTransport}}),
				client.WithKeys(client.NewKeys(nil)))
		}
		k := derived.NewKeys(kc, nil)
		k.Check(ctx, x.ns, false)
		reason, lacks := k.Skip(x.ns)
		if (reason != "") != x.reason || lacks != x.lacksKeys || k.Skipped(x.ns) != reason {
			t.Errorf("%s: Skip = %q, %v", x.name, reason, lacks)
		}
	}
}
