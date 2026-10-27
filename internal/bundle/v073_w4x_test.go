package bundle_test

import (
	"bytes"
	"crypto/ecdh"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// w4x (P35 x bundles), §G.5.1 "Plaintext of protected sources", §2.1
// Protection, Addendum E Levels: once a sealed namespace is raised to e2e,
// its history from before the raise is still served sealed, and the
// exporter's client opens it, so a bundle carries it in plaintext under
// access "e2e". The export is refused unsealed, as it was while the
// namespace was sealed, unless the bundle is sealed to recipients or
// plaintext is asked for.
func TestV073W4xBundleOfNamespaceRaisedFromSealed(t *testing.T) {
	t.Parallel()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks})
	t0 := s.Now()
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}}))
	jwk, priv, _ := seal.GenerateRecipient()
	c := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"e"}, []string{"read", "create", "append", "config"},
		map[string]any{"enc": jwk, "nbf": t0.Format(time.RFC3339)})), client.WithKeys(client.NewKeys(priv)))
	const secret = "pre-raise-secret-w4x"
	d0 := must(c.Create(ctx, "e", "d", nonce(op("add", "", map[string]any{"v": secret})))).ID
	sel := []string{"e/d"}
	exportErr(t, c, bundle.ExportOptions{Select: sel}, "private or sealed")
	s.Clock.Advance(time.Minute)
	h := must(c.NSHead(ctx, "e"))
	must(c.PatchConfig(ctx, "e", h.Config, ops(op("replace", "/encryption", map[string]any{"level": "e2e", "epoch": 2.0}))))
	x := c.E2E(priv)
	must(x.InitKeyring(ctx, "e"))
	must(x.AppendSealed(ctx, "e", "d", d0, ops(op("add", "/x", 1.0))))

	exportErr(t, c, bundle.ExportOptions{Select: sel}, "private or sealed")
	var plain bytes.Buffer
	_, sum, err := bundle.Export(ctx, c, &plain, bundle.ExportOptions{Select: sel, Plaintext: true})
	noErr(t, err)
	if sum.Header.Access["e"] != bundle.AccessE2E || !bytes.Contains(plain.Bytes(), []byte(secret)) {
		t.Fatalf("export asked for in plaintext: access %v, the pre-raise content in it: %v", sum.Header.Access, bytes.Contains(plain.Bytes(), []byte(secret)))
	}
	reader := identity(t)
	var sealed bytes.Buffer
	_, _, err = bundle.Export(ctx, c, &sealed, bundle.ExportOptions{Select: sel, Recipients: []*ecdh.PublicKey{reader.PublicKey()}})
	noErr(t, err)
	if bytes.Contains(sealed.Bytes(), []byte(secret)) {
		t.Fatal("export sealed to a recipient carries the pre-raise content in the clear")
	}
}
