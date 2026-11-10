package derived_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// fakeEpoch1Keys answers POST /ns/e/keys for epoch 1 with keys of its own
// choosing, as a server could: a sender-less raw key and an entry wrapped
// by a sender the service knows but doesn't trust. Other requests pass.
type fakeEpoch1Keys struct {
	rt   http.RoundTripper
	keys []any
	n    *atomic.Int64
}

func (f fakeEpoch1Keys) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != "POST" || r.URL.Path != "/ns/e/keys" {
		return f.rt.RoundTrip(r)
	}
	f.n.Add(1)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(body, []byte(`"epochs":[1]`)) {
		r.Body = io.NopCloser(bytes.NewReader(body))
		return f.rt.RoundTrip(r)
	}
	b := jsonv.Canonical(map[string]any{"level": "e2e", "epoch": 3.0, "keys": f.keys})
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)), Request: r}, nil
}

// E2E-8 (SERVICES §E.2.6 Getting keys, SPEC §E.3.2: a client opens and
// seals only under a key whose from it trusts; Addendum E Levels, v0.78: a
// namespace is e2e from its creation, so no epoch of it was ever served as
// at E2). A service takes the key of every epoch of an e2e namespace from
// a keyring sender it trusts (client.E2E.SealKey), never a sender-less key
// /keys gives, even for an epoch the keyring names no key of. Here the
// keyring names e#2 and e#3 from the admin, whom the service trusts, and
// e#2 for the service only from a sender it knows but doesn't trust; /keys
// relays for e#1 a raw key and an entry from that sender. v0.26.1 took the
// raw key as a pre-raise epoch's (preRaiseKey).
func TestV081E2ENoSenderlessKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks})
	k := clienttest.NewKey("k")
	if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "e2e", "epoch": 2.0}}); err != nil {
		t.Fatal(err)
	}
	adminJWK, admin, _ := seal.GenerateRecipient()
	_, evil, _ := seal.GenerateRecipient()
	svcJWK, svc, _ := seal.GenerateRecipient()
	nbf := s.Now().Add(-time.Hour).Format(time.RFC3339)
	ac := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"e"}, []string{"read", "create", "append", "config"},
		map[string]any{"enc": adminJWK, "nbf": nbf})))
	ax := ac.E2E(admin)
	if _, err := ax.InitKeyring(ctx, "e"); err != nil {
		t.Fatal(err)
	}
	kr, head, err := ax.Keyring(ctx, "e")
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Add(evil, svc.PublicKey(), "e#2", seal.NewKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := ac.Append(ctx, "e", client.KeyringName, head, []any{map[string]any{"op": "replace", "path": "", "value": kr.Value()}}); err != nil {
		t.Fatal(err)
	}
	if e, err := ax.RotateEpoch(ctx, "e", svc.PublicKey()); err != nil || e != 3 {
		t.Fatalf("rotate: %d %v", e, err)
	}

	raw := seal.NewKey()
	relayed, err := seal.WrapKeyAuth(evil, svc.PublicKey(), "e#1", "", seal.NewKey())
	if err != nil {
		t.Fatal(err)
	}
	relayed.From = seal.Thumbprint(evil.PublicKey())
	var n atomic.Int64
	fake := []any{map[string]any{"kid": "e#1", "key": base64.RawURLEncoding.EncodeToString(raw)}, relayed.Value()}
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:x", []string{"e"}, []string{"read"}, map[string]any{"enc": svcJWK, "nbf": nbf})),
		client.WithKeyringSenders(evil.PublicKey()), client.WithTrustedKeyringSenders(admin.PublicKey()),
		client.WithTransport(func(rt http.RoundTripper) http.RoundTripper { return fakeEpoch1Keys{rt, fake, &n} }))
	keys := derived.NewKeys(sc, svc)
	if in, err := keys.Info(ctx, "e"); err != nil || in.Level != derived.LevelE2E || in.Epoch != 3 {
		t.Fatalf("info: %+v %v", in, err)
	}
	if _, err := keys.EpochKey(ctx, "e", 3); err != nil {
		t.Fatalf("the current epoch, from the admin: %v", err)
	}
	got, err := keys.EpochKey(ctx, "e", 1)
	if !errors.Is(err, client.ErrUntrustedKey) {
		t.Fatalf("an epoch the keyring names no key of, for which /keys relays a raw key and an untrusted entry: %x, %v; want ErrUntrustedKey", got, err)
	}
	if _, err := keys.KeyAt(ctx, "e", 1); !errors.Is(err, client.ErrUntrustedKey) {
		t.Fatalf("KeyAt: %v, want ErrUntrustedKey", err)
	}

	// Ported from TestV073W4xServicePreRaiseEpochKey: a keyring epoch whose
	// only entry for the service is from a sender it doesn't trust stays
	// ErrUntrustedKey, and the failure is answered again for a while
	// without asking POST /keys anew.
	if _, err := keys.EpochKey(ctx, "e", 2); !errors.Is(err, client.ErrUntrustedKey) {
		t.Fatalf("a keyring epoch whose only entry for the service is untrusted: %v, want ErrUntrustedKey", err)
	}
	before := n.Load()
	for range 5 {
		for _, e := range []int{1, 2} {
			if _, err := keys.EpochKey(ctx, "e", e); !errors.Is(err, client.ErrUntrustedKey) {
				t.Fatalf("e#%d again: %v", e, err)
			}
		}
	}
	if d := n.Load() - before; d != 0 {
		t.Fatalf("a failed EpochKey asked POST /keys %d more times at once, want it answered again", d)
	}
}

// E2E-8: with only a sender-less key for an epoch, a service has no key
// for it (ErrNoKeys), as before: nothing there was ever trusted.
func TestV081E2ESenderlessKeyAlone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("admin"))
	if _, err := c.CreateNamespace(ctx, "e", map[string]any{"encryption": map[string]any{"level": "e2e", "epoch": 3.0}}); err != nil {
		t.Fatal(err)
	}
	_, svc, _ := seal.GenerateRecipient()
	var n atomic.Int64
	fake := []any{map[string]any{"kid": "e#1", "key": base64.RawURLEncoding.EncodeToString(seal.NewKey())}}
	sc := s.Client(t, client.WithAuthor("svc"), client.WithTransport(func(rt http.RoundTripper) http.RoundTripper { return fakeEpoch1Keys{rt, fake, &n} }))
	keys := derived.NewKeys(sc, svc)
	if _, err := keys.EpochKey(ctx, "e", 1); err == nil || !strings.Contains(err.Error(), "e#1") {
		t.Fatalf("a sender-less key alone: %v, want no key", err)
	}
	if n.Load() == 0 {
		t.Fatal("the fake /keys was never asked")
	}
}
