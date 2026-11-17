package client_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// A copy made with With keeps the keyring senders (WithKeyringSenders),
// so its E2E views open the entries the admin wrapped, as the original's
// do, with senders added to the copy alone.
func TestWithKeepsKeyringSenders(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t)})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "e", map[string]any{"encryption": map[string]any{"level": "e2e"}}))
	_, adminPriv, _ := seal.GenerateRecipient()
	_, readerPriv, _ := seal.GenerateRecipient()
	_, otherPriv, _ := seal.GenerateRecipient()
	ad := c.E2E(adminPriv)
	must(ad.InitKeyring(ctx, "e", readerPriv.PublicKey()))
	must(ad.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1}))

	rc := s.Client(t, client.WithAuthor("bob"), client.WithKeyringSenders(adminPriv.PublicKey()))
	cp := rc.With(client.WithAuthor("carol"), client.WithKeyringSenders(otherPriv.PublicKey()))
	for _, x := range []*client.Client{cp, rc} {
		_, d, err := x.E2E(readerPriv).LoadE2E(ctx, "e", "d")
		if err != nil {
			t.Fatal(err)
		}
		sameJSON(t, d.Value, map[string]any{"n": 1})
	}
}
