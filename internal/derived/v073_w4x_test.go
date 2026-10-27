package derived_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

type countKeys struct {
	rt http.RoundTripper
	n  *atomic.Int64
}

func (c countKeys) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/keys") {
		c.n.Add(1)
	}
	return c.rt.RoundTrip(r)
}

// w4x (P36 x P37), Addendum E Levels, §E.2.6, §E.3.2: a service whose Info
// already says e2e takes the key of an epoch from before a raise from
// sealed as a sealed namespace's is, from /keys without a sender (the
// server held that content and its key before the raise), so it seals
// views of pre-raise revisions after a restart too. It never takes a
// sender-less key for a keyring epoch: one whose only keyring entry for
// the service is from a sender it doesn't trust stays ErrUntrustedKey.
// A failure is answered again for a while without asking /keys anew.
func TestV073W4xServicePreRaiseEpochKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks})
	t0 := s.Now()
	k := clienttest.NewKey("k")
	if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}}); err != nil {
		t.Fatal(err)
	}
	adminJWK, admin, _ := seal.GenerateRecipient()
	_, evil, _ := seal.GenerateRecipient()
	svcJWK, svc, _ := seal.GenerateRecipient()
	nbf := map[string]any{"nbf": t0.Format(time.RFC3339)}
	ac := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"e"}, []string{"read", "create", "append", "config"},
		map[string]any{"enc": adminJWK, "nbf": nbf["nbf"]})), client.WithKeys(client.NewKeys(admin)))
	if _, err := ac.Create(ctx, "e", "a", append(client.GenesisPatches(map[string]any{"v": 1.0}), map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})); err != nil {
		t.Fatal(err)
	}
	pre, err := ac.FetchKeys(ctx, "e", []int{1}, nil)
	if err != nil || len(pre) != 1 {
		t.Fatalf("e#1 at E2: %v %v", pre, err)
	}
	e1, err := seal.UnwrapKey(admin, pre[0].Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	s.Clock.Advance(time.Minute)
	h, err := ac.NSHead(ctx, "e")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ac.PatchConfig(ctx, "e", h.Config, []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 2.0}}}); err != nil {
		t.Fatal(err)
	}
	ax := ac.E2E(admin)
	if _, err := ax.InitKeyring(ctx, "e"); err != nil {
		t.Fatal(err)
	}
	// e#2's entry for the service is from a sender it knows but doesn't
	// trust, around a key of that sender's choosing; then e#3, the current
	// epoch, for nobody but the admin.
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
	if _, err := ax.RotateEpoch(ctx, "e"); err != nil {
		t.Fatal(err)
	}

	var n atomic.Int64
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:x", []string{"e"}, []string{"read"}, map[string]any{"enc": svcJWK, "nbf": nbf["nbf"]})),
		client.WithKeyringSenders(evil.PublicKey()), client.WithTrustedKeyringSenders(admin.PublicKey()),
		client.WithTransport(func(rt http.RoundTripper) http.RoundTripper { return countKeys{rt, &n} }))
	keys := derived.NewKeys(sc, svc)
	in, err := keys.Info(ctx, "e")
	if err != nil || in.Level != derived.LevelE2E || in.Epoch != 3 {
		t.Fatalf("info: %+v %v", in, err)
	}
	got, err := keys.EpochKey(ctx, "e", 1)
	if err != nil {
		t.Fatalf("the epoch before the raise, Info already e2e: %v", err)
	}
	if !bytes.Equal(got, e1) {
		t.Fatal("the epoch before the raise: not the key the namespace sealed under")
	}
	if _, err := keys.EpochKey(ctx, "e", 2); !errors.Is(err, client.ErrUntrustedKey) {
		t.Fatalf("a keyring epoch whose only entry for the service is untrusted: %v, want ErrUntrustedKey", err)
	}
	before := n.Load()
	for range 5 {
		if _, err := keys.EpochKey(ctx, "e", 2); !errors.Is(err, client.ErrUntrustedKey) {
			t.Fatalf("again: %v", err)
		}
	}
	if d := n.Load() - before; d != 0 {
		t.Fatalf("a failed EpochKey asked POST /keys %d more times at once, want it answered again", d)
	}
}
