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
	"github.com/middle-management/patchlog/internal/seal"
)

// An epoch key that can't be fetched for the moment (the relay's POST
// /keys and the keyring both cut off, or answered 503) is that failure,
// which asking again may mend (client.Transient), not ErrNoKeys: a
// service waiting for the namespace keeps waiting (§E.3, §B.5). Refused
// (a 403), it is ErrNoKeys.
func TestE2EKeyTransient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "secret"))).CreateNamespace(ctx, "secret",
		map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}))
	svcJWK, svcPriv, _ := seal.GenerateRecipient()
	wJWK, wPriv, _ := seal.GenerateRecipient()
	wr := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"secret"}, []string{"read", "create", "append", "config"}, map[string]any{"enc": wJWK})))
	must(wr.E2E(wPriv).InitKeyring(ctx, "secret", svcPriv.PublicKey()))
	kr, _, err := wr.E2E(wPriv).Keyring(ctx, "secret")
	if err != nil {
		t.Fatal(err)
	}
	kid := seal.Kid("secret", kr.Current)
	var mode atomic.Value
	base := http.DefaultTransport.(*http.Transport).Clone()
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/ns/secret/keys" || strings.Contains(req.URL.Path, client.KeyringName) {
			switch mode.Load() {
			case "reset":
				return nil, errors.New("connection reset by peer")
			case "503", "403":
				st := map[string]int{"503": http.StatusServiceUnavailable, "403": http.StatusForbidden}[mode.Load().(string)]
				return &http.Response{StatusCode: st, Header: http.Header{"Content-Type": {"application/json"}},
					Body: io.NopCloser(strings.NewReader(`{"error":"x"}`)), Request: req}, nil
			}
		}
		return base.RoundTrip(req)
	})
	svc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"secret"}, []string{"read"}, map[string]any{"enc": svcJWK})),
		client.WithHTTPClient(&http.Client{Transport: rt}))
	for _, m := range []string{"reset", "503"} {
		mode.Store(m)
		_, err := svc.E2E(svcPriv).Key(ctx, kid)
		if err == nil || errors.Is(err, client.ErrNoKeys) || !client.Transient(err) {
			t.Errorf("%s: %v, want a transient failure, not ErrNoKeys", m, err)
		}
	}
	mode.Store("403")
	if _, err := svc.E2E(svcPriv).Key(ctx, kid); !errors.Is(err, client.ErrNoKeys) {
		t.Errorf("403: %v, want ErrNoKeys", err)
	}
	mode.Store("")
	if _, err := svc.E2E(svcPriv).Key(ctx, kid); err != nil {
		t.Fatalf("answered: %v", err)
	}
}
