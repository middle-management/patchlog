package main

// patchlog e2e migrate-keyring -api URL -ns NS -identity admin.jwk [-reader pub.jwk]... [-current-reader pub.jwk]... [-bearer T] [-json]
//
// Wraps an e2e namespace's keyring stored in the format before v0.63 again
// as the keyring document of §E.3.2 (client.E2E.MigrateKeyring): every
// epoch's key, which -identity opens from its own entry, is wrapped in HPKE
// auth mode under -identity for the readers named, and for -identity
// itself. The stored recipient lists aren't used: anyone could have
// written them, and a reader left out of a rotation must not get its key
// now (§E.2.4), so the readers come from the caller.

import (
	"context"
	"crypto/ecdh"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/seal"
)

const e2eUsage = `usage:
  patchlog e2e migrate-keyring -api URL -ns NS -identity admin.jwk [-reader pub.jwk]... [-current-reader pub.jwk]... [-bearer T] [-author A] [-json]`

func e2eCmd(args []string) {
	if len(args) == 0 || args[0] != "migrate-keyring" {
		fmt.Fprintln(os.Stderr, e2eUsage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet("e2e migrate-keyring", flag.ExitOnError)
	tf := addToolFlags(fs)
	ns := fs.String("ns", "", "e2e namespace whose keyring to wrap again")
	identity := fs.String("identity", "", "file with the admin's X25519 private key (a private JWK {kty, crv, x, d}, or base64url d): it opens its own entry of every epoch, and wraps the new entries in auth mode, so readers name it as the keyring's sender (§E.3.2)")
	var readers, current multi
	fs.Var(&readers, "reader", "file with a reader's X25519 public key (a JWK {kty, crv, x}, or base64url x), given every epoch the keyring holds (repeatable)")
	fs.Var(&current, "current-reader", "as -reader, but given only the keyring's newest epoch, as a reader added since the last rotation is (repeatable)")
	fs.Parse(args[1:])
	if *ns == "" || *identity == "" {
		fmt.Fprintln(os.Stderr, "e2e migrate-keyring: -ns and -identity are required")
		os.Exit(2)
	}
	b, err := os.ReadFile(*identity)
	if err != nil {
		toolFatal(err)
	}
	admin, err := seal.ParseRecipientPrivate(b)
	if err != nil {
		toolFatal(fmt.Errorf("-identity %s: %w", *identity, err))
	}
	all, err := readPublicKeys(readers)
	if err != nil {
		toolFatal(err)
	}
	newest, err := readPublicKeys(current)
	if err != nil {
		toolFatal(err)
	}
	ctx := context.Background()
	x := tf.client().E2E(admin)
	old, _, err := x.LegacyKeyring(ctx, *ns)
	if err != nil {
		toolFatal(err)
	}
	epochs := make([]int, 0, len(old.Epochs))
	for e := range old.Epochs {
		epochs = append(epochs, e)
	}
	w, err := x.MigrateKeyring(ctx, *ns, migrationReaders(epochs, all, newest))
	if err != nil {
		toolFatal(err)
	}
	if *tf.asJSON {
		printJSON(map[string]any{"ns": *ns, "keyring": w.ID})
		return
	}
	fmt.Printf("keyring of %s wrapped again as revision %s; readers name %s as its sender\n", *ns, w.ID, seal.Thumbprint(admin.PublicKey()))
}

// migrationReaders gives each of epochs the readers of all, and the newest
// of them also those of newest (seal.MigrateKeyring wants every epoch
// named, an empty list leaving it to the admin alone).
func migrationReaders(epochs []int, all, newest []*ecdh.PublicKey) map[int][]*ecdh.PublicKey {
	out := make(map[int][]*ecdh.PublicKey, len(epochs))
	if len(epochs) == 0 {
		return out
	}
	sort.Ints(epochs)
	for _, e := range epochs {
		out[e] = append([]*ecdh.PublicKey(nil), all...)
	}
	last := epochs[len(epochs)-1]
	out[last] = append(out[last], newest...)
	return out
}

// readPublicKeys reads X25519 public keys from files: a JWK {kty, crv, x},
// or the bare base64url x.
func readPublicKeys(files []string) ([]*ecdh.PublicKey, error) {
	var out []*ecdh.PublicKey
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		s := strings.TrimSpace(string(b))
		var v any = []byte(s)
		if !strings.HasPrefix(s, "{") {
			v = map[string]any{"kty": "OKP", "crv": "X25519", "x": s}
		}
		pub, err := seal.ParseRecipientJWK(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, pub)
	}
	return out, nil
}
