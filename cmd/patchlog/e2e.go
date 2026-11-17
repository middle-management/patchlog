package main

// patchlog e2e: keyring administration of e2e namespaces (§E.3.2), and
// what the encrypted namespaces' keys look like from the command line.
//
//	patchlog e2e init NS [READER.jwk…] --identity ADMIN.jwk
//	patchlog e2e add-reader NS READER.jwk… [--history] --identity ADMIN.jwk
//	patchlog e2e rotate NS [READER.jwk…] [--yes] --identity ADMIN.jwk
//	patchlog e2e readers NS [KEY.jwk…] [--identity KEY.jwk]
//	patchlog e2e keys NS [--epoch E]… [--resource NAME]… [--identity KEY.jwk] [--show-keys]
//	patchlog e2e seal-status --api URL --ns NS --name NAME [--bearer T] [--json]
//
// init, add-reader and rotate write the namespace's plaintext keyring
// resource through client.E2E (InitKeyring, AddReader, RotateEpoch): each
// entry an epoch key wrapped in HPKE auth mode under the admin's key,
// --identity, to a reader's public key. Readers then read and write the
// namespace's documents with get, put, patch, log and blob, given
// --identity (their private key) and --keyring-sender (the admin's public
// key), encrypted.go. Keys are made with patchlog bundle keygen -o KEY.jwk,
// which prints the public JWK to hand out. readers lists the keyring's
// entries by thumbprint; keys shows what POST /ns/{ns}/keys gives the
// grant, for debugging, printing key material only with --show-keys.
//
// seal-status:
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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// migrateKeyringRemoved is what patchlog e2e migrate-keyring answers.
const migrateKeyringRemoved = "e2e migrate-keyring was removed in v0.81: no client reads a keyring in the format before v0.63 any more (v0.78). Run the v0.26.1 client's patchlog e2e migrate-keyring before upgrading."

// e2eCmd is patchlog e2e.
type e2eCmd struct {
	Init       *e2eInitCmd      `arg:"subcommand:init" help:"create an e2e namespace's keyring: a fresh key for its current epoch, wrapped for you and the readers given (§E.3.2)"`
	AddReader  *e2eAddReaderCmd `arg:"subcommand:add-reader" help:"wrap the current epoch's key (with --history, every epoch's) for more readers"`
	Rotate     *e2eRotateCmd    `arg:"subcommand:rotate" help:"start a new epoch, its key wrapped only for you and the readers given: the others can't read what is written from then on (§E.3.2)"`
	Readers    *e2eReadersCmd   `arg:"subcommand:readers" help:"list an e2e namespace's keyring: whom each epoch's key is wrapped to, and by whom"`
	Keys       *e2eKeysCmd      `arg:"subcommand:keys" help:"show the epochs and keys POST /ns/{ns}/keys gives the grant (debugging; key material only with --show-keys)"`
	SealStatus *sealStatusCmd   `arg:"subcommand:seal-status" help:"report how near a resource's K_r of the current epoch is to the message bound (§E.2.1)"`
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

// keyringAdminArgs is --identity, of init, add-reader and rotate.
type keyringAdminArgs struct {
	Identity string `arg:"--identity,env:PATCHLOG_IDENTITY" placeholder:"ADMIN.JWK" help:"file with the keyring admin's X25519 private key (a private JWK, as patchlog bundle keygen -o ADMIN.JWK writes it, or base64url d), required: it wraps the keyring's entries in HPKE auth mode, as their from, and always gets the key itself; readers name its public key with --keyring-sender"`
}

// admin returns the e2e view of c whose own key, --identity, wraps the
// keyring's entries.
func (k *keyringAdminArgs) admin(c *client.Client) (*client.E2E, error) {
	if k.Identity == "" {
		return nil, errors.New("--identity ADMIN.jwk (or $PATCHLOG_IDENTITY) is required: the keyring admin's X25519 private key, which wraps the entries (make one with patchlog bundle keygen -o ADMIN.jwk)")
	}
	priv, err := readIdentity(k.Identity)
	if err != nil {
		return nil, err
	}
	return c.E2E(priv), nil
}

// keyLabels names thumbprints for display: the public keys in files by
// their base names, and you's (--identity) as "you".
func keyLabels(you *ecdh.PrivateKey, files ...string) (map[string]string, error) {
	m := map[string]string{}
	for _, f := range files {
		pubs, err := readPublicKeys([]string{f})
		if err != nil {
			return nil, err
		}
		m[seal.Thumbprint(pubs[0])] = filepath.Base(f)
	}
	if you != nil {
		m[seal.Thumbprint(you.PublicKey())] = "you"
	}
	return m, nil
}

// labelled is thumbprint tp with its label, if it has one.
func labelled(labels map[string]string, tp string) string {
	if l := labels[tp]; l != "" {
		return tp + " (" + l + ")"
	}
	return tp
}

// others counts the distinct keys among readers other than self.
func others(self *ecdh.PublicKey, readers []*ecdh.PublicKey) int {
	seen := map[string]bool{seal.Thumbprint(self): true}
	n := 0
	for _, r := range readers {
		if tp := seal.Thumbprint(r); !seen[tp] {
			seen[tp] = true
			n++
		}
	}
	return n
}

// readerKeys reads the readers' public keys of files.
func readerKeys(files []string) ([]*ecdh.PublicKey, error) {
	pubs, err := readPublicKeys(files)
	if err != nil {
		return nil, fmt.Errorf("reader key: %w", err)
	}
	return pubs, nil
}

// e2eInitCmd is patchlog e2e init NS [READER.jwk…].
type e2eInitCmd struct {
	toolArgs
	keyringAdminArgs
	NS      string   `arg:"positional,required"`
	Readers []string `arg:"positional" placeholder:"READER.JWK" help:"files with readers' X25519 public keys (a JWK {kty, crv, x}, as patchlog bundle keygen prints it, or base64url x), to wrap the key for besides yours"`
}

func (a *e2eInitCmd) run(string) { runClient(a) }

func (a *e2eInitCmd) exec(ctx context.Context, out, errw io.Writer) error {
	x, err := a.admin(a.writer())
	if err != nil {
		return err
	}
	readers, err := readerKeys(a.Readers)
	if err != nil {
		return err
	}
	w, err := x.InitKeyring(ctx, a.NS, readers...)
	if err != nil {
		return err
	}
	what := fmt.Sprintf("created the keyring of %s, its key wrapped for you and %d more", a.NS, others(x.PublicKey(), readers))
	if kr, _, err := x.Keyring(ctx, a.NS); err == nil {
		what = fmt.Sprintf("created the keyring of %s: the key of %s, wrapped for you and %d more", a.NS, seal.Kid(a.NS, kr.Current(a.NS)), others(x.PublicKey(), readers))
	}
	return a.wrote(out, errw, what, w.ID, w.NSID, w.Gesture)
}

// e2eAddReaderCmd is patchlog e2e add-reader NS READER.jwk….
type e2eAddReaderCmd struct {
	toolArgs
	keyringAdminArgs
	History bool     `arg:"--history" help:"also wrap every older epoch's key you hold, so the readers read what was written before (default: the current epoch's only)"`
	NS      string   `arg:"positional,required"`
	Readers []string `arg:"positional,required" placeholder:"READER.JWK" help:"files with readers' X25519 public keys (a JWK {kty, crv, x}, as patchlog bundle keygen prints it, or base64url x); each is a keyring write of its own"`
}

func (a *e2eAddReaderCmd) run(string) { runClient(a) }

func (a *e2eAddReaderCmd) exec(ctx context.Context, out, errw io.Writer) error {
	x, err := a.admin(a.writer())
	if err != nil {
		return err
	}
	readers, err := readerKeys(a.Readers)
	if err != nil {
		return err
	}
	which := "the current key"
	if a.History {
		which = "the keys"
	}
	for i, r := range readers {
		w, err := x.AddReader(ctx, a.NS, r, a.History)
		if err != nil {
			return fmt.Errorf("adding %s: %w", a.Readers[i], err)
		}
		what := fmt.Sprintf("wrapped %s of %s for %s (%s)", which, a.NS, seal.Thumbprint(r), filepath.Base(a.Readers[i]))
		if err := a.wrote(out, errw, what, w.ID, w.NSID, w.Gesture); err != nil {
			return err
		}
	}
	return nil
}

// e2eRotateCmd is patchlog e2e rotate NS [READER.jwk…].
type e2eRotateCmd struct {
	toolArgs
	keyringAdminArgs
	Yes     bool     `arg:"--yes" help:"rotate even though readers of the current epoch aren't given: they can't read what is written from then on (without it, they are listed and nothing is written)"`
	NS      string   `arg:"positional,required"`
	Readers []string `arg:"positional" placeholder:"READER.JWK" help:"files with the X25519 public keys of the readers to keep (a JWK, or base64url x); you, and the --keyring-sender keys that hold the current key, are kept too"`
}

func (a *e2eRotateCmd) run(string) { runClient(a) }

func (a *e2eRotateCmd) exec(ctx context.Context, out, errw io.Writer) error {
	x, err := a.admin(a.writer())
	if err != nil {
		return err
	}
	given, err := readerKeys(a.Readers)
	if err != nil {
		return err
	}
	kr, _, err := x.Keyring(ctx, a.NS)
	if err != nil {
		return err
	}
	readers := append(given, x.KeyringReaders(kr)...)
	keep := map[string]bool{seal.Thumbprint(x.PublicKey()): true}
	for _, r := range readers {
		keep[seal.Thumbprint(r)] = true
	}
	kid := seal.Kid(a.NS, kr.Current(a.NS))
	dropped := []string{}
	for _, tp := range kr.Recipients(kid) {
		if !keep[tp] {
			dropped = append(dropped, tp)
		}
	}
	if len(dropped) > 0 && !a.Yes {
		fmt.Fprintf(errw, "the key of %s is wrapped for %d readers not given, who couldn't read what is written after the rotation:\n", kid, len(dropped))
		for _, tp := range dropped {
			fmt.Fprintf(errw, "  %s\n", tp)
		}
		return fmt.Errorf("not rotating %s: give those readers' public keys as READER.jwk to keep them, or --yes to revoke them", a.NS)
	}
	e, err := x.RotateEpoch(ctx, a.NS, readers...)
	if err != nil {
		return err
	}
	head := ""
	if _, h, err := x.Keyring(ctx, a.NS); err == nil {
		head = h
	}
	if a.JSON {
		return writeJSON(out, map[string]any{"epoch": e, "keyring": head, "revoked": dropped})
	}
	fmt.Fprintf(errw, "rotated %s to epoch %d: its key wrapped for you and %d more", a.NS, e, others(x.PublicKey(), readers))
	if len(dropped) > 0 {
		fmt.Fprintf(errw, "; %d readers revoked", len(dropped))
	}
	fmt.Fprintf(errw, " (keyring revision %s)\n", head)
	fmt.Fprintln(out, head)
	return nil
}

// e2eReadersCmd is patchlog e2e readers NS [KEY.jwk…].
type e2eReadersCmd struct {
	toolArgs
	encArgs
	NS   string   `arg:"positional,required"`
	Keys []string `arg:"positional" placeholder:"KEY.JWK" help:"files with public keys to name in the listing by their file names, as --keyring-sender's and --trusted-sender's are (--identity's is named you)"`
}

func (a *e2eReadersCmd) run(string) { runClient(a) }

func (a *e2eReadersCmd) exec(ctx context.Context, out, errw io.Writer) error {
	var you *ecdh.PrivateKey
	if a.Identity != "" {
		var err error
		if you, err = readIdentity(a.Identity); err != nil {
			return err
		}
	}
	files := append(append(append([]string{}, a.KeyringSender...), a.TrustedSender...), a.Keys...)
	labels, err := keyLabels(you, files...)
	if err != nil {
		return err
	}
	kr, head, err := a.client().E2E(nil).Keyring(ctx, a.NS)
	if client.IsNotFound(err) {
		return fmt.Errorf("%s has no keyring: it isn't an e2e namespace, or patchlog e2e init hasn't run (%w)", a.NS, err)
	}
	if err != nil {
		return err
	}
	if a.JSON {
		keys := []any{}
		for _, e := range kr.Entries {
			m := map[string]any{"kid": e.Kid, "to": e.To, "from": e.From}
			if l := labels[e.To]; l != "" {
				m["toName"] = l
			}
			if l := labels[e.From]; l != "" {
				m["fromName"] = l
			}
			keys = append(keys, m)
		}
		return writeJSON(out, map[string]any{"keyring": head, "epoch": kr.Current(a.NS), "keys": keys})
	}
	fmt.Fprintf(errw, "keyring of %s at %s: %d entries, current epoch %d\n", a.NS, head, len(kr.Entries), kr.Current(a.NS))
	for _, e := range kr.Entries {
		fmt.Fprintf(out, "%s  to %s  from %s\n", e.Kid, labelled(labels, e.To), labelled(labels, e.From))
	}
	return nil
}

// e2eKeysCmd is patchlog e2e keys NS.
type e2eKeysCmd struct {
	toolArgs
	encArgs
	Epoch    []int    `arg:"--epoch,separate" placeholder:"E" help:"ask for this epoch's keys (repeatable; default: every epoch the grant may have)"`
	Resource []string `arg:"--resource,separate" placeholder:"NAME" help:"ask for this resource's key K_r, as a grant whose rules fix /resource gets (repeatable; sealed namespaces)"`
	ShowKeys bool     `arg:"--show-keys" help:"print the keys themselves (base64url), unwrapped with --identity where they are wrapped: secrets, for debugging only"`
	NS       string   `arg:"positional,required"`
}

func (a *e2eKeysCmd) run(string) { runClient(a) }

func (a *e2eKeysCmd) exec(ctx context.Context, out, errw io.Writer) error {
	var you *ecdh.PrivateKey
	if a.Identity != "" {
		var err error
		if you, err = readIdentity(a.Identity); err != nil {
			return err
		}
	}
	senderFiles := append(append([]string{}, a.KeyringSender...), a.TrustedSender...)
	senders, err := readPublicKeys(senderFiles)
	if err != nil {
		return err
	}
	if you != nil {
		senders = append(senders, you.PublicKey())
	}
	labels, err := keyLabels(you, senderFiles...)
	if err != nil {
		return err
	}
	var epochs []int
	if len(a.Epoch) > 0 {
		epochs = a.Epoch
	}
	ans, err := a.client().FetchKeysAnswer(ctx, a.NS, epochs, a.Resource)
	if client.IsNotOffered(err) {
		return fmt.Errorf("%s is neither sealed nor e2e: /keys has no keys to give (%w)", a.NS, err)
	}
	if err != nil {
		return err
	}
	rows := []any{}
	if !a.JSON {
		fmt.Fprintf(out, "%s: level %s, epoch %d, pad %t, %d keys\n", a.NS, ans.Level, ans.Epoch, ans.Pad, len(ans.Keys))
	}
	for _, k := range ans.Keys {
		key, form, status := k.Key, "raw", ""
		var uerr error
		if key == nil {
			form = "wrapped"
			if you == nil {
				status = "give --identity to unwrap it"
			} else if key, uerr = seal.UnwrapRelayed(you, k.Wrapped, senders); uerr != nil {
				status = "doesn't open with --identity: " + uerr.Error()
			} else {
				status = "opens with --identity"
			}
		}
		if a.JSON {
			m := map[string]any{"kid": k.Kid, "form": form}
			if k.Resource != "" {
				m["name"] = k.Resource
			}
			if k.From != "" {
				m["from"] = k.From
			}
			if form == "wrapped" && you != nil {
				m["opens"] = uerr == nil
				if uerr != nil {
					m["error"] = uerr.Error()
				}
			}
			if a.ShowKeys && key != nil {
				m["key"] = base64.RawURLEncoding.EncodeToString(key)
			}
			rows = append(rows, m)
			continue
		}
		line := k.Kid
		if k.Resource != "" {
			line += "  name " + k.Resource
		}
		line += "  " + form
		if k.From != "" {
			line += "  from " + labelled(labels, k.From)
		}
		if status != "" {
			line += "  " + status
		}
		if a.ShowKeys && key != nil {
			line += "  key " + base64.RawURLEncoding.EncodeToString(key)
		}
		fmt.Fprintln(out, line)
	}
	if a.JSON {
		return writeJSON(out, map[string]any{"ns": a.NS, "level": ans.Level, "epoch": ans.Epoch, "pad": ans.Pad, "keys": rows})
	}
	if len(ans.Keys) == 0 {
		fmt.Fprintln(errw, "no keys: the grant gets none of the epochs asked for (without an nbf, only the current one's), or, at e2e, no keyring entry is wrapped to its enc")
	}
	return nil
}
