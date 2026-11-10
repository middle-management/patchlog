package core

import (
	"context"
	"crypto/ecdh"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// §E.3.2, §C.7 (v0.76, v0.81): the start warnings name what mends a
// keyring /keys relays nothing from. One of the §E.3.2 form whose $nonce
// was written before v0.76 (played with LegacyKeyringNonceForTests) is
// mended by the next keyring write of a v0.81 client, which writes a fresh
// $nonce; migrate-keyring, which only wraps pre-v0.63 keyrings again, is
// advised for one in that format only (played with a raise that
// LegacyE2ERaiseForTests lets through, over a plaintext keyring).
func TestV081LegacyKeyringWarnings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := p29Engine(t)
	_, admin, _ := seal.GenerateRecipient()
	_, reader, _ := seal.GenerateRecipient()
	k1 := seal.NewKey()
	write := func(ns string, doc any) {
		t.Helper()
		if _, err := e.WriteResource(ctx, p29Req(ns), Item{Resource: KeyringName, IfNoneMatch: true, Steps: []Step{{Patches: []any{p29Add("", doc)}}}}); err != nil {
			t.Fatalf("%s: %v", ns, err)
		}
	}
	ring := func(ns, nonce string) map[string]any {
		t.Helper()
		kr, err := seal.BuildKeyringV2(admin, ns, 1, k1, []*ecdh.PublicKey{reader.PublicKey()})
		if err != nil {
			t.Fatal(err)
		}
		d := kr.Value()
		if nonce != "" {
			d["$nonce"] = nonce
		}
		return d
	}
	e2e := map[string]any{"encryption": map[string]any{"level": "e2e"}}
	for _, ns := range []string{"fresh", "none", "old"} {
		mkNS(t, e, ns, e2e)
	}
	write("fresh", ring("fresh", seal.NewNonce()))
	write("none", ring("none", ""))
	e.opt.LegacyKeyringNonceForTests = true
	write("old", ring("old", "pre-v0.76 nonce"))
	e.opt.LegacyKeyringNonceForTests = false
	mkNS(t, e, "legacy", map[string]any{})
	legacy, err := seal.BuildKeyring("legacy", 1, k1, []*ecdh.PublicKey{reader.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	write("legacy", legacy.Value())
	e.opt.LegacyE2ERaiseForTests = true
	h, err := e.NamespaceHead(ctx, "legacy", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.WriteConfig(ctx, p29Req("legacy"), ConfigChange{IfMatch: h.Config, Patches: []any{p29Add("/encryption", e2e["encryption"])}}); err != nil {
		t.Fatal(err)
	}
	e.opt.LegacyE2ERaiseForTests = false

	got := map[string]string{}
	for _, l := range e.legacyE2EWarnings(ctx, nil) {
		ns, _, _ := strings.Cut(strings.TrimPrefix(l, "namespace "), ":")
		got[ns] = l
	}
	if len(got) != 2 || got["fresh"] != "" || got["none"] != "" {
		t.Fatalf("warnings %q, want old's and legacy's", got)
	}
	if l := got["old"]; !strings.Contains(l, "before v0.76") || !strings.Contains(l, "v0.81 client") || !strings.Contains(l, "RotateEpoch") || strings.Contains(l, "migrate-keyring") {
		t.Fatalf("warning for a pre-v0.76 $nonce: %q", l)
	}
	if l := got["legacy"]; !strings.Contains(l, "before v0.63") || !strings.Contains(l, "v0.26.1 client's patchlog e2e migrate-keyring") {
		t.Fatalf("warning for a pre-v0.63 keyring: %q", l)
	}
}
