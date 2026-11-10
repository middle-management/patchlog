package server

import (
	"context"
	"crypto/ed25519"
	"testing"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

func withLegacyKeyringNonce(o *core.Options) { o.LegacyKeyringNonceForTests = true }

// §E.3.2, §C.7 (v0.76, v0.81): a keyring stored before v0.76 with a
// $nonce of another form (the gate took any then; LegacyKeyringNonceForTests
// plays it) has its entries relayed by /keys no more (keyringEntries), and
// a keyring write must carry a fresh $nonce or none. The v0.81 client
// writes a fresh one in place of the stored one, so a key holder adding a
// reader (even one it has) or rotating mends the keyring; it used to copy
// the stored one, and every keyring write of such a namespace was 422.
func TestV081KeyringPreV076NonceWrittenAgain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var opPriv ed25519.PrivateKey
	base := []envOpt{withAuth(&opPriv), withKeyStore(newKeyStore(t)), withEncTuning, withoutRetentionLoop}
	e, reopen := v073Reopenable(t, append(base, withLegacyKeyringNonce)...)
	e.opPriv = opPriv
	admin := newKey("admin")
	adminJWK, adminPriv, _ := seal.GenerateRecipient()
	readerJWK, readerPriv, _ := seal.GenerateRecipient()
	nss := []string{"add", "touch", "rot"}
	for _, ns := range nss {
		e.mkNS(ns, e2eDoc(map[string]any{"keys": []any{admin.entry("*")}}))
	}
	e2e := func(e *tenv) *plclient.E2E {
		t.Helper()
		c, err := plclient.New(e.srv.URL, plclient.WithBearer(e.grant(admin, "user:admin", nss, allVerbs, map[string]any{"enc": adminJWK})))
		if err != nil {
			t.Fatal(err)
		}
		return c.E2E(adminPriv)
	}
	// relayed is how many entries /keys relays to the grant of enc.
	relayed := func(e *tenv, ns string, enc map[string]any) int {
		t.Helper()
		_, r := e.keysOf(ns, nil, e.grant(admin, "user:r", []string{ns}, []string{"read"}, map[string]any{"enc": enc}))
		return len(keyEntries(t, r))
	}
	x := e2e(e)
	for _, ns := range nss {
		if _, err := x.InitKeyring(ctx, ns); err != nil {
			t.Fatal(err)
		}
		kr, head, err := x.Keyring(ctx, ns)
		if err != nil {
			t.Fatal(err)
		}
		old := kr.Value()
		old["$nonce"] = "pre-v0.76 nonce"
		expect(t, e.write("PATCH", ns, "keyring", head, ops(op("replace", "", old)), e.grant(admin, "user:admin", nss, allVerbs)), 201)
		if n := relayed(e, ns, adminJWK); n != 0 {
			t.Fatalf("%s: /keys relayed %d entries of a keyring with a pre-v0.76 $nonce", ns, n)
		}
	}
	// v0.81 takes no keyring write with such a $nonce.
	e = reopen(func(o *core.Options) { o.LegacyKeyringNonceForTests = false })
	e.opPriv = opPriv
	x = e2e(e)
	readerPub := readerPriv.PublicKey()
	if _, err := x.AddReader(ctx, "add", readerPub, false); err != nil {
		t.Fatalf("AddReader over a keyring with a pre-v0.76 $nonce: %v", err)
	}
	// Adding a reader it has, here the key holder itself, is a write too.
	if _, err := x.AddReader(ctx, "touch", adminPriv.PublicKey(), false); err != nil {
		t.Fatalf("AddReader of a reader it has over a keyring with a pre-v0.76 $nonce: %v", err)
	}
	if ep, err := x.RotateEpoch(ctx, "rot", readerPub); err != nil || ep != 2 {
		t.Fatalf("RotateEpoch over a keyring with a pre-v0.76 $nonce: %d %v", ep, err)
	}
	for _, ns := range nss {
		kr, _, err := x.Keyring(ctx, ns)
		if err != nil {
			t.Fatal(err)
		}
		if !seal.ValidNonce(kr.Nonce) {
			t.Fatalf("%s: stored $nonce %q after the write", ns, kr.Nonce)
		}
		readers := 1
		if ns == "touch" {
			readers = 0
		}
		if relayed(e, ns, adminJWK) == 0 || relayed(e, ns, readerJWK) != readers {
			t.Fatalf("%s: /keys relays nothing after the write", ns)
		}
	}
	// The reader opens the current epoch's key, relayed.
	c, err := plclient.New(e.srv.URL, plclient.WithBearer(e.grant(admin, "user:r", []string{"rot"}, []string{"read"}, map[string]any{"enc": readerJWK})))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.E2E(readerPriv).WithSenders(adminPriv.PublicKey()).Key(ctx, "rot#2"); err != nil {
		t.Fatalf("reader's key of rot#2: %v", err)
	}
}
