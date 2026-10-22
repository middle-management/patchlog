package bundle_test

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/seal"
)

// keyringOf is a keyring document (§E.3.2) holding key, the K_e of epoch
// of ns, for a fresh recipient that wrapped it itself.
func keyringOf(t *testing.T, ns string, epoch int, key []byte) *seal.KeyringV2 {
	t.Helper()
	id := identity(t)
	kr, err := seal.BuildKeyringV2(id, ns, epoch, key, []*ecdh.PublicKey{id.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// e2eKeyringDocs writes a full-history bundle of e2e namespace ns whose
// keyring revisions are the documents given, so a keyring history can
// hold the format before v0.63, and one document, name, with the patch
// sets given.
func e2eKeyringDocs(t *testing.T, ns, name string, keyrings []map[string]any, patchSets ...[]any) []byte {
	t.Helper()
	chain := func(res string, sets [][]any) (ls []bundle.Line, head string) {
		for _, ps := range sets {
			v := must(client.ToValue(ps))
			id := must(client.ExpectedRevision(head, v))
			ls = append(ls, bundle.Line{NS: ns, Resource: res, ID: id, Parent: head, Kind: "rev", Patches: v})
			head = id
		}
		return ls, head
	}
	h := bundle.Header{Origin: stagingOrigin, Created: "2026-10-01T00:00:00Z", At: map[string]string{ns: ids.Hash(nil, []byte(ns)).String()},
		Docs: map[string]bundle.DocInfo{}, Access: map[string]string{ns: bundle.AccessE2E}}
	sets := [][]any{client.GenesisPatches(keyrings[0])}
	for _, kr := range keyrings[1:] {
		sets = append(sets, ops(op("replace", "", kr)))
	}
	all, head := chain("keyring", sets)
	h.Docs[bundle.Key(ns, "keyring")] = bundle.DocInfo{History: bundle.Full, Head: head}
	ls, head := chain(name, patchSets)
	h.Docs[bundle.Key(ns, name)] = bundle.DocInfo{History: bundle.Full, Head: head}
	all = append(all, ls...)
	var buf bytes.Buffer
	w := must(bundle.NewWriter(&buf, h))
	for _, l := range all {
		noErr(t, w.Line(l))
	}
	must(w.Close())
	return buf.Bytes()
}

// P18 review (ENC-11, §G.5.1): an e2e target's gate refuses every keyring
// revision in the format before v0.63, a bundle's history included, so a
// bundle whose keyring history holds one (migrated at the source or not)
// is refused at step 1, before anything is written, with the reason, and
// so is a keyring line that isn't a keyring document at all.
func TestV073LegacyKeyringHistoryAtStep1(t *testing.T) {
	t.Parallel()
	k1 := seal.NewKey()
	reader := identity(t)
	legacy := must(seal.BuildKeyring("e", 1, k1, []*ecdh.PublicKey{reader.PublicKey()})).Value()
	migrated := must(seal.BuildKeyringV2(reader, "e", 1, k1, []*ecdh.PublicKey{reader.PublicKey()})).Value()
	g := client.GenesisPatches(map[string]any{"v": 1.0})
	for name, c := range map[string]struct {
		keyrings []map[string]any
		want     string
	}{
		"legacy then migrated": {[]map[string]any{legacy, migrated}, "keyring in the format before v0.63"},
		"legacy head":          {[]map[string]any{migrated, legacy}, "keyring in the format before v0.63"},
		"not a keyring":        {[]map[string]any{{"keys": "none"}, migrated}, "isn't a keyring document"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := e2eKeyringDocs(t, "e", "d", c.keyrings, sealedSet(t, k1, "e#1", "e", "d", "", g))
			dst := newEncDeployment(t, cmsOrigin)
			_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
			var ae *bundle.AccessError
			if !errors.As(err, &ae) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("import: %v", err)
			}
			if _, err := dst.c.NSHead(ctx, "e"); !client.IsNotFound(err) {
				t.Fatalf("written before the refusal: %v", err)
			}
		})
	}
	// The same history in the keyring document format imports.
	b := e2eKeyringDocs(t, "e", "d", []map[string]any{migrated}, sealedSet(t, k1, "e#1", "e", "d", "", g))
	must(bundle.Import(ctx, newEncDeployment(t, cmsOrigin).c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true}))
}
