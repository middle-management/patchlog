package main

// patchlog e2e seal-status --api URL --ns NS --name NAME [--bearer T] [--json]
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
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// migrateKeyringRemoved is what patchlog e2e migrate-keyring answers.
const migrateKeyringRemoved = "e2e migrate-keyring was removed in v0.81: no client reads a keyring in the format before v0.63 any more (v0.78). Run the v0.26.1 client's patchlog e2e migrate-keyring before upgrading."

// e2eCmd is patchlog e2e.
type e2eCmd struct {
	SealStatus *sealStatusCmd `arg:"subcommand:seal-status" help:"report how near a resource's K_r of the current epoch is to the message bound (§E.2.1)"`
}

// removedCommand is the message of a command that was removed, given its
// arguments, or "".
func removedCommand(args []string) string {
	if len(args) >= 2 && args[0] == "e2e" && args[1] == "migrate-keyring" {
		return migrateKeyringRemoved
	}
	return ""
}

type sealStatusCmd struct {
	toolArgs
	NS   string `arg:"--ns,required" help:"e2e namespace"`
	Name string `arg:"--name,required" help:"resource whose K_r of the current epoch to report on"`
}

func (a *sealStatusCmd) run(string) {
	if code := a.sealStatus(os.Stdout, os.Stderr); code != 0 {
		os.Exit(code)
	}
}

// sealStatus runs seal-status and returns its exit status.
func (a *sealStatusCmd) sealStatus(stdout, stderr io.Writer) int {
	st, err := a.client().E2E(nil).SealStatus(context.Background(), a.NS, a.Name)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if a.JSON {
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

// options returns the client options of kf (client.WithKeyringSenders,
// client.WithTrustedKeyringSenders, client.WithExpectedLevel).
func (kf *keyringArgs) options() ([]client.Option, error) {
	senders, err := readPublicKeys(kf.KeyringSender)
	if err != nil {
		return nil, fmt.Errorf("--keyring-sender: %w", err)
	}
	trusted, err := readPublicKeys(kf.TrustedSender)
	if err != nil {
		return nil, fmt.Errorf("--trusted-sender: %w", err)
	}
	var out []client.Option
	if len(senders) > 0 {
		out = append(out, client.WithKeyringSenders(senders...))
	}
	if len(trusted) > 0 {
		out = append(out, client.WithTrustedKeyringSenders(trusted...))
	}
	levels, err := expectLevels(kf.ExpectLevel)
	if err != nil {
		return nil, err
	}
	return append(out, levels...), nil
}

// expectLevels are the client options of --expect-level's values, each
// "ns=level" (client.WithExpectedLevel): a namespace name and one of
// at-rest, sealed and e2e, anything else being an error, never ignored.
func expectLevels(vals []string) ([]client.Option, error) {
	var out []client.Option
	for _, v := range vals {
		ns, level, ok := strings.Cut(v, "=")
		if !ok || !client.ValidNSName(ns) || !client.ValidLevel(level) {
			return nil, fmt.Errorf("--expect-level: %q isn't ns=level with level at-rest, sealed or e2e", v)
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
