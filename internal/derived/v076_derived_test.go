package derived_test

import (
	"context"
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// TestV076DerivedNoRecipientLacking (ENC-5, FSVC-13; §A.4, §E.2.6
// Getting keys; changelog v0.76 "a wrapped key no recipient key opens is
// lacking, not 503 behind"): the epoch key a service seals views under,
// which /keys gives wrapped to its grant's enc while no recipient key is
// configured, is ErrNoKeys: lacking (follow.LacksKey), not retried
// (derived.Retryable). Before v0.76 it was a plain error.
func TestV076DerivedNoRecipientLacking(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks})
	k := clienttest.NewKey("k")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec")))
	if _, err := op.CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}); err != nil {
		t.Fatal(err)
	}
	jwk, _, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	c := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"}, map[string]any{"enc": jwk})),
		client.WithKeys(client.NewKeys(nil)))
	// The epoch key alone, as a service holding the namespace's level
	// asks for it: the namespace document, sealed too, needs the
	// client's keys, which lack the recipient key alike.
	_, err = derived.NewKeys(c, nil).EpochKey(ctx, "sec", 1)
	if !errors.Is(err, client.ErrNoKeys) || !follow.LacksKey(ctx, err) || derived.Retryable(err) {
		t.Fatalf("an epoch key wrapped to the grant's enc, no recipient key: %v (ErrNoKeys %v, LacksKey %v, Retryable %v), want lacking",
			err, errors.Is(err, client.ErrNoKeys), follow.LacksKey(ctx, err), derived.Retryable(err))
	}
}
