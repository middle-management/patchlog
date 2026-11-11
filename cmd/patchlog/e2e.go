package main

// patchlog e2e seal-status -api URL -ns NS -name NAME [-bearer T] [-json]
//
// Reports how near the resource's K_r of the current epoch is to the
// message bound (§E.2.1: at E3 only clients seal under K_r, and the key
// holder that rotates keeps each within it), as client.E2E.SealStatus
// counts it from the resource's log: rotation due once the margin is
// reached, when a holder of a * key rotates the epoch.
//
// patchlog e2e migrate-keyring was removed in v0.81: no client reads a
// keyring in the format before v0.63 any more (v0.78, "Reading this
// spec"). A key holder runs the v0.26.1 client's migrate-keyring before
// upgrading.

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

const e2eUsage = `usage:
  patchlog e2e seal-status -api URL -ns NS -name NAME [-bearer T] [-json]`

// migrateKeyringRemoved is what patchlog e2e migrate-keyring answers.
const migrateKeyringRemoved = "e2e migrate-keyring was removed in v0.81: no client reads a keyring in the format before v0.63 any more (v0.78). Run the v0.26.1 client's patchlog e2e migrate-keyring before upgrading."

func e2eCmd(args []string) {
	os.Exit(runE2E(args, os.Stdout, os.Stderr))
}

// runE2E runs patchlog e2e with args and returns its exit status.
func runE2E(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, e2eUsage)
		return 2
	}
	switch args[0] {
	case "migrate-keyring":
		fmt.Fprintln(stderr, migrateKeyringRemoved)
		return 1
	case "seal-status":
	default:
		fmt.Fprintln(stderr, e2eUsage)
		return 2
	}
	fs := flag.NewFlagSet("e2e seal-status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tf := addToolFlags(fs)
	ns := fs.String("ns", "", "e2e namespace")
	name := fs.String("name", "", "resource whose K_r of the current epoch to report on")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *ns == "" || *name == "" {
		fmt.Fprintln(stderr, "e2e seal-status: -ns and -name are required")
		return 2
	}
	st, err := tf.client().E2E(nil).SealStatus(context.Background(), *ns, *name)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if *tf.asJSON {
		b, _ := json.MarshalIndent(map[string]any{"ns": st.NS, "name": st.Name, "kid": st.Kid, "sealed": st.Sealed,
			"partial": st.Partial, "bound": st.Bound, "margin": st.Margin, "rotationDue": st.RotationDue}, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	fmt.Fprintln(stdout, sealStatusLine(st))
	return 0
}

// sealStatusLine is seal-status's line for st.
func sealStatusLine(st *client.SealStatus) string {
	s := fmt.Sprintf("%s/%s under %s: %d sealings of %d", st.NS, st.Name, st.Kid, st.Sealed, st.Bound)
	if st.Partial {
		s += " (at least: some of the log couldn't be counted)"
	}
	if st.RotationDue {
		s += "; rotation due: a holder of a * key rotates the epoch (§E.2.1)"
	}
	return s
}

// keyringFlags name the admin keys whose e2e keyring entries a tool or
// service opens, and those it trusts to distribute keys it seals under
// (§E.3.2): -keyring-sender and -trusted-sender, both repeatable; and the
// encryption levels it expects of namespaces, -expect-level (§7.1).
type keyringFlags struct{ senders, trusted, levels multi }

const keyringSenderHelp = "file with a keyring admin's X25519 public key (a JWK {kty, crv, x}, or base64url x): e2e keyring entries it wrapped are opened (§E.3.2), and, unless -trusted-sender is given, sealed under; repeatable"
const trustedSenderHelp = "as -keyring-sender, and trusted to distribute keys: once any is given, this tool seals (writes, prunes, re-encrypted merges, derived views) only under keys whose keyring entry is from one of these or from its own identity, while reads still open keys from every -keyring-sender (§E.3.2); never under a key without a sender; repeatable"

const expectLevelHelp = "ns=level: the encryption level namespace ns is known to have (at-rest, sealed or e2e). The tool holds it from its first request, so a server or cache that claims a lower one is refused, and with e2e a document served in the clear is too (§7.1, Levels); without it a level is only held once learnt, in this process; repeatable"

// addKeyringFlags registers -keyring-sender, -trusted-sender and
// -expect-level on fs.
func addKeyringFlags(fs *flag.FlagSet) *keyringFlags {
	kf := &keyringFlags{}
	fs.Var(&kf.senders, "keyring-sender", keyringSenderHelp)
	fs.Var(&kf.trusted, "trusted-sender", trustedSenderHelp)
	fs.Var(&kf.levels, "expect-level", expectLevelHelp)
	return kf
}

// options returns the client options of kf (client.WithKeyringSenders,
// client.WithTrustedKeyringSenders, client.WithExpectedLevel).
func (kf *keyringFlags) options() ([]client.Option, error) {
	senders, err := readPublicKeys(kf.senders)
	if err != nil {
		return nil, fmt.Errorf("-keyring-sender: %w", err)
	}
	trusted, err := readPublicKeys(kf.trusted)
	if err != nil {
		return nil, fmt.Errorf("-trusted-sender: %w", err)
	}
	var out []client.Option
	if len(senders) > 0 {
		out = append(out, client.WithKeyringSenders(senders...))
	}
	if len(trusted) > 0 {
		out = append(out, client.WithTrustedKeyringSenders(trusted...))
	}
	levels, err := expectLevels(kf.levels)
	if err != nil {
		return nil, err
	}
	return append(out, levels...), nil
}

// expectLevels are the client options of -expect-level's values, each
// "ns=level" (client.WithExpectedLevel): a namespace name and one of
// at-rest, sealed and e2e, anything else being an error, never ignored.
func expectLevels(vals []string) ([]client.Option, error) {
	var out []client.Option
	for _, v := range vals {
		ns, level, ok := strings.Cut(v, "=")
		if !ok || !client.ValidNSName(ns) || !client.ValidLevel(level) {
			return nil, fmt.Errorf("-expect-level: %q isn't ns=level with level at-rest, sealed or e2e", v)
		}
		out = append(out, client.WithExpectedLevel(ns, level))
	}
	return out, nil
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
