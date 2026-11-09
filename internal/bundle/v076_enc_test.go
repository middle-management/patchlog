package bundle_test

import (
	"crypto/ecdh"
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// §E.3.2, §C.7 (v0.76): an e2e target's gate refuses a keyring revision
// whose $nonce isn't of the fresh form, a bundle's history included, so a
// bundle whose keyring history holds one (written before v0.76, when any
// string was taken) is refused at step 1, before anything is written; one
// with a fresh $nonce imports.
func TestV076KeyringNonceAtStep1(t *testing.T) {
	t.Parallel()
	k1 := seal.NewKey()
	reader := identity(t)
	kr := must(seal.BuildKeyringV2(reader, "e", 1, k1, []*ecdh.PublicKey{reader.PublicKey()}))
	g := client.GenesisPatches(map[string]any{"v": 1.0})
	stale, fresh := kr.Value(), kr.Value()
	stale["$nonce"], fresh["$nonce"] = "x", seal.NewNonce()
	b := e2eKeyringDocs(t, "e", "d", []map[string]any{stale, fresh}, sealedSet(t, k1, "e#1", "e", "d", "", g))
	dst := newEncDeployment(t, cmsOrigin)
	_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	var ae *bundle.AccessError
	if !errors.As(err, &ae) || !strings.Contains(err.Error(), "fresh form") {
		t.Fatalf("import: %v", err)
	}
	if _, err := dst.c.NSHead(ctx, "e"); !client.IsNotFound(err) {
		t.Fatalf("written before the refusal: %v", err)
	}
	b = e2eKeyringDocs(t, "e", "d", []map[string]any{fresh}, sealedSet(t, k1, "e#1", "e", "d", "", g))
	must(bundle.Import(ctx, newEncDeployment(t, cmsOrigin).c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true}))
}
