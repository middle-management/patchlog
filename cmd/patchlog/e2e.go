package main

// patchlog e2e migrate-keyring -api URL -ns NS -identity admin.jwk [-reader pub.jwk]... [-current-reader pub.jwk]... [-skip-unopenable] [-bearer T] [-json]
//
// Wraps an e2e namespace's keyring stored in the format before v0.63 again
// as the keyring document of §E.3.2 (client.E2E.MigrateKeyring): every
// epoch's key, which -identity opens from its own entry, is wrapped in HPKE
// auth mode under -identity for the readers named, and for -identity
// itself. The stored recipient lists aren't used: anyone could have
// written them, and a reader left out of a rotation must not get its key
// now (§E.2.4), so the readers come from the caller.
//
// With -skip-unopenable, a key holder that can't open every epoch (one
// added at a later epoch) wraps the epochs it opens, the newest among them,
// and leaves out the others (client.E2E.MigrateKeyringOpenable), so the
// namespace can be rotated again. Run on a keyring already migrated, the
// command puts back, from the keyring's last revision in the old format,
// the epochs a migration left out.

import (
	"context"
	"crypto/ecdh"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

const e2eUsage = `usage:
  patchlog e2e migrate-keyring -api URL -ns NS -identity admin.jwk [-reader pub.jwk]... [-current-reader pub.jwk]... [-skip-unopenable] [-bearer T] [-author A] [-json]`

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
	skip := fs.Bool("skip-unopenable", false, "leave out the epochs -identity can't open (it must open the newest), so a key holder added at a later epoch can migrate and then rotate; the keys left out stay in the keyring's history until a holder of them runs migrate-keyring again")
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
	old, epochs, err := x.MigrationSource(ctx, *ns)
	if err != nil {
		toolFatal(err)
	}
	readersOf := migrationReaders(epochs, old.Current, all, newest)
	var w *client.WriteResult
	var left []int
	if *skip {
		w, left, err = x.MigrateKeyringOpenable(ctx, *ns, readersOf)
	} else {
		w, err = x.MigrateKeyring(ctx, *ns, readersOf)
	}
	if err != nil {
		toolFatal(err)
	}
	if *tf.asJSON {
		out := map[string]any{"ns": *ns, "left": left}
		if w != nil {
			out["keyring"] = w.ID
		}
		printJSON(out)
		return
	}
	if w == nil {
		fmt.Printf("keyring of %s: no epoch to wrap again\n", *ns)
	} else {
		fmt.Printf("keyring of %s wrapped again as revision %s; readers name %s as its sender\n", *ns, w.ID, seal.Thumbprint(admin.PublicKey()))
	}
	if len(left) > 0 {
		fmt.Printf("left out epochs %v, which %s can't open: a holder of them runs migrate-keyring again to put them back\n", left, *identity)
	}
}

// migrationReaders gives each of epochs the readers of all, and epoch
// current, the old keyring's newest, if among them, also those of newest
// (MigrateKeyring wants every epoch named, an empty list leaving it to
// the admin alone).
func migrationReaders(epochs []int, current int, all, newest []*ecdh.PublicKey) map[int][]*ecdh.PublicKey {
	out := make(map[int][]*ecdh.PublicKey, len(epochs))
	for _, e := range epochs {
		out[e] = append([]*ecdh.PublicKey(nil), all...)
	}
	if _, ok := out[current]; ok {
		out[current] = append(out[current], newest...)
	}
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
