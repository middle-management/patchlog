package main

// Encrypted namespaces (Addendum E) from the ordinary client commands. get,
// put, patch, log and blob put/get learn the namespace's encryption level
// (client.EncryptionLevel, or for a grant that can't read the namespace
// document what POST /ns/{ns}/keys names, §C.5) and take the encrypted
// path where it is sealed or e2e, so one command line works at every level:
//
//   - Sealed (E.2): the server seals what it serves, and the client opens
//     it with the keys POST /ns/{ns}/keys gives the grant (client.WithKeys):
//     raw, or wrapped to the grant's enc, which --identity, the private key
//     of that enc, unwraps. Writes stay plaintext and add a fresh $nonce
//     (§E.2: every create and append sets one), and blobs are uploaded with
//     a nonce and read through their reference (client.GetBlobRef).
//   - End-to-end (E.3): the client seals and folds (client.E2E). --identity
//     is the private key the namespace's keyring wraps its keys to; the
//     admin who wrapped them is named with --keyring-sender (or
//     --trusted-sender). Without --identity the commands refuse, rather
//     than print ciphertext. Folds flag revisions that don't open, validate
//     or match (§E.3.2): the document is printed all the same, with a
//     warning per flag on stderr. The keyring resource is plaintext and
//     read and written as in any namespace.
//
// A delete (rm) writes no content, so it is the same at every level.

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/seal"
)

// encArgs is --identity, of the client commands that read or write
// documents.
type encArgs struct {
	Identity string `arg:"--identity,env:PATCHLOG_IDENTITY" placeholder:"KEY.JWK" help:"file with your X25519 private key (a private JWK, as patchlog bundle keygen -o KEY.JWK writes it, or base64url d), for encrypted namespaces (Addendum E): in an e2e namespace, the key its keyring wraps the keys to, which reading and writing documents needs; in a sealed one, the private key of --bearer's enc, which /keys wraps the keys to"`
}

// readIdentity reads an X25519 private key from file: a private JWK
// {kty, crv, x, d}, or the bare base64url d.
func readIdentity(file string) (*ecdh.PrivateKey, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("--identity: %w", err)
	}
	priv, err := seal.ParseRecipientPrivate(b)
	if err != nil {
		return nil, fmt.Errorf("--identity %s: %w", file, err)
	}
	return priv, nil
}

// encView is a client set up for the level of one resource's namespace.
type encView struct {
	c        *client.Client // opens sealed content with the keys /keys gives
	x        *client.E2E    // set where ns/name is sealed end to end
	priv     *ecdh.PrivateKey
	level    string
	ns, name string
}

// view returns c set up for ns/name: it learns the namespace's level, keys
// c for sealed content (unwrapping with --identity, if given), and for a
// resource of an e2e namespace other than its keyring makes the E2E view,
// which needs --identity.
func (e *encArgs) view(ctx context.Context, c *client.Client, ns, name string) (*encView, error) {
	v := &encView{ns: ns, name: name}
	if e.Identity != "" {
		var err error
		if v.priv, err = readIdentity(e.Identity); err != nil {
			return nil, err
		}
	}
	v.c = c.With(client.WithKeys(client.NewKeys(v.priv)))
	var err error
	if v.level, err = nsLevel(ctx, v.c, ns); err != nil {
		return nil, err
	}
	if v.level == "e2e" && name != client.KeyringName {
		if v.priv == nil {
			return nil, needIdentity(ns)
		}
		v.x = v.c.E2E(v.priv)
	}
	return v, nil
}

// needIdentity is the error for a command on an e2e namespace's document
// without --identity.
func needIdentity(ns string) error {
	return fmt.Errorf("namespace %s is end-to-end encrypted (Addendum E.3): its documents are sealed and read by the client, with --identity KEY.jwk (or $PATCHLOG_IDENTITY), the X25519 private key its keyring wraps the keys to, and --keyring-sender ADMIN.jwk, the public key of the admin who wrapped them (make a key with patchlog bundle keygen -o KEY.jwk; a key holder adds its public key with patchlog e2e add-reader)", ns)
}

// nsLevel is ns's encryption level ("" for none): from its namespace
// document, or for a grant that can't read it (§C.5) from what /keys
// names; where neither tells, the level c holds (--expect-level), and the
// plain path's own requests report what is wrong. One lower than held is
// client.ErrLevelLowered.
func nsLevel(ctx context.Context, c *client.Client, ns string) (string, error) {
	lv, err := c.EncryptionLevel(ctx, ns)
	if err == nil || errors.Is(err, client.ErrLevelLowered) || !client.IsAuth(err) && !client.IsNotFound(err) {
		return lv, err
	}
	a, kerr := c.FetchKeysAnswer(ctx, ns, []int{}, nil)
	switch {
	case kerr == nil && a.Level != "":
		return a.Level, nil
	case errors.Is(kerr, client.ErrLevelLowered):
		return "", kerr
	}
	return c.HeldLevel(ns), nil
}

// e2e reports whether ns/name is read and written through the E2E view.
func (v *encView) e2e() bool { return v.x != nil }

// sealed reports whether ns is sealed (E.2).
func (v *encView) sealed() bool { return v.level == "sealed" }

// explain adds what to do to an error of a read or write of ns/name.
func (v *encView) explain(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, client.ErrUntrustedKey):
		return fmt.Errorf("%s/%s: %w (--trusted-sender names the keyring admins whose keys this tool seals under)", v.ns, v.name, err)
	case !errors.Is(err, client.ErrNoKeys):
		if v.level == "" && client.IsNotOffered(err) {
			return fmt.Errorf("%w (where %s is end-to-end encrypted, the server can't serve it: see --identity)", err, v.ns)
		}
		return err
	case v.e2e():
		return fmt.Errorf("%s/%s: no key of --identity's opens it: the keyring holds none for it, or its entry is from an admin whose public key isn't given with --keyring-sender ADMIN.jwk: %w", v.ns, v.name, err)
	case v.priv == nil:
		return fmt.Errorf("namespace %s is sealed (Addendum E.2) and no key opens it without a private key: where --bearer's grant carries enc, /keys wraps its keys to it, and --identity KEY.jwk (or $PATCHLOG_IDENTITY) is that enc's private key: %w", v.ns, err)
	}
	return fmt.Errorf("namespace %s is sealed (Addendum E.2) and no key the grant gets opens it: it gets none for that epoch or resource, or its enc isn't --identity's key: %w", v.ns, err)
}

// doc reads the document of ns/name at revision id, folding it in an e2e
// namespace (E2E.DocE2E), with what the fold flagged.
func (v *encView) doc(ctx context.Context, id string) (*client.Doc, []client.Flag, error) {
	if !v.e2e() {
		d, err := v.c.Doc(ctx, v.ns, v.name, id)
		return d, nil, v.explain(err)
	}
	d, err := v.x.DocE2E(ctx, v.ns, v.name, id)
	if err != nil {
		return nil, nil, v.explain(err)
	}
	return &client.Doc{ID: id, Value: d.Value}, d.Flagged, nil
}

// warnFlags prints a warning for each revision a fold flagged (§E.3.2).
func (v *encView) warnFlags(errw io.Writer, flags []client.Flag) {
	for _, f := range flags {
		fmt.Fprintf(errw, "warning: %s/%s: revision %s by %s is flagged: %s\n", v.ns, v.name, f.ID, f.Author, f.Message)
	}
}

// log reads ns/name's log after since: in an e2e namespace with the patch
// sets opened (E2E.OpenLog), a revision that doesn't open having none and
// its reason in flags, at the same index.
func (v *encView) log(ctx context.Context, since string) ([]client.LogEntry, []string, error) {
	if !v.e2e() {
		es, err := v.c.Log(ctx, v.ns, v.name, "", since)
		return es, make([]string, len(es)), v.explain(err)
	}
	es, err := v.x.Log(ctx, v.ns, v.name, "", since)
	if err != nil {
		return nil, nil, v.explain(err)
	}
	out, flags, err := v.x.OpenLog(ctx, v.ns, v.name, es)
	return out, flags, v.explain(err)
}

// openedRaw is e's entry as served, with its patch set replaced by the one
// OpenLog opened, or, where it didn't open, by flag.
func openedRaw(e client.LogEntry, flag string) map[string]any {
	m := make(map[string]any, len(e.Raw)+1)
	for k, x := range e.Raw {
		m[k] = x
	}
	switch {
	case flag != "":
		delete(m, "patches")
		m["flag"] = flag
	case e.HasPatches:
		m["patches"] = e.Patches
	}
	return m
}

// withNonce is patches, a JSON Patch array, with a fresh $nonce added, as
// a sealed namespace needs of every create and append (§E.2, §C.7).
// Anything else is returned as it is, for the server to refuse.
func withNonce(patches any) any {
	a, ok := patches.([]any)
	if !ok {
		return patches
	}
	return append(append([]any{}, a...), map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
}

// create creates ns/name holding doc: sealed by the client in an e2e
// namespace, with a fresh $nonce in a sealed one.
func (v *encView) create(ctx context.Context, doc any, opts ...client.WriteOption) (*client.WriteResult, error) {
	var w *client.WriteResult
	var err error
	switch {
	case v.e2e():
		w, err = v.x.CreateDocSealed(ctx, v.ns, v.name, doc, opts...)
	case v.sealed():
		w, err = v.c.Create(ctx, v.ns, v.name, withNonce(client.GenesisPatches(doc)), opts...)
	default:
		w, err = v.c.CreateDoc(ctx, v.ns, v.name, doc, opts...)
	}
	return w, v.explain(err)
}

// e2eAppendAttempts bounds how often an e2e append to the head seals
// again after losing a race (412 stale).
const e2eAppendAttempts = 5

// append appends patches to ns/name: on ifRev only, else on the head,
// trying again on the new head when another writer gets there first. In
// an e2e namespace the client seals them (E2E.AppendSealed), sealing again
// for each new head; in a sealed one each attempt adds a fresh $nonce.
func (v *encView) append(ctx context.Context, ifRev string, patches any, opts ...client.WriteOption) (*client.WriteResult, error) {
	if v.e2e() {
		for attempt := 1; ; attempt++ {
			head := ifRev
			if head == "" {
				var err error
				if head, err = liveHead(ctx, v.c, v.ns, v.name); err != nil {
					return nil, err
				}
			}
			w, err := v.x.AppendSealed(ctx, v.ns, v.name, head, patches, opts...)
			if ifRev == "" && client.IsStale(err) && attempt < e2eAppendAttempts {
				continue
			}
			return w, v.explain(err)
		}
	}
	build := func(string) (any, error) {
		if v.sealed() {
			return withNonce(patches), nil
		}
		return patches, nil
	}
	if ifRev != "" {
		p, _ := build(ifRev)
		return v.c.Append(ctx, v.ns, v.name, ifRev, p, opts...)
	}
	head, err := liveHead(ctx, v.c, v.ns, v.name)
	if err != nil {
		return nil, err
	}
	return v.c.AppendLatest(ctx, v.ns, v.name, head, client.Backoff{}, build, opts...)
}

// refAt returns the blob reference at ptr of ns/name's document (at rev,
// else the head).
func (v *encView) refAt(ctx context.Context, rev, ptr string) (map[string]any, error) {
	p, err := pointer.Parse(ptr)
	if err != nil {
		return nil, fmt.Errorf("--at: %w", err)
	}
	if rev == "" {
		if rev, err = liveHead(ctx, v.c, v.ns, v.name); err != nil {
			return nil, err
		}
	}
	d, _, err := v.doc(ctx, rev)
	if err != nil {
		return nil, err
	}
	x, ok := pointer.Get(d.Value, p)
	ref, _ := x.(map[string]any)
	if bid, _ := ref["$blob"].(string); !ok || bid == "" {
		return nil, fmt.Errorf("%s/%s has no blob reference at %s", v.ns, v.name, ptr)
	}
	return ref, nil
}
