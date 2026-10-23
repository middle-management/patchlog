package client

// End-to-end namespaces (Addendum E, level E3).
//
// The server of an e2e namespace never sees plaintext: clients seal patch
// sets before writing and fold the log themselves when reading. E2E is the
// key-holding view of a Client that does both:
//
//   - Writes (CreateSealed, AppendSealed, RestoreSealed) seal the patch set
//     with seal.SealPatchSet under the resource's K_r = HKDF(K_e, ns, name)
//     of the namespace's current epoch, bound to {ns, name, parent}, and
//     resend exactly the same bytes on a retry, so the id stays the same
//     (§E.3.1). Unless WithoutValidation, the resulting document is
//     validated against its $schema first (§E.3.2: validation moves to
//     clients); a create applies to the document null (§6.2 step 3).
//   - Reads (DocE2E, LoadE2E) follow the X-E2E: fold redirect of
//     /r/{ns}/{name}/rev/{id} to the log, open every sealed patch set
//     (checking kid, pl {ns, name, parent}, the id chain and each id over the
//     ciphertext), fold from genesis or, when the redirect's since is a
//     pruning horizon, from its sealed snapshot, which /rev/{since} serves
//     (never the log, §7.1 Paging, §8.6), and verify every intermediate
//     document that has a $schema. /rev/{id} of a horizon answers its
//     snapshot directly (X-E2E: snapshot).
//     Patch sets and snapshots open under K_r, or under K_e, which sealed
//     them before v0.65. A revision that doesn't validate, declares the
//     wrong blobs or isn't padded is flagged with its author and still
//     folded; one that doesn't open or apply is flagged and folded as []
//     (§E.3.2). A base's namespace in pl and kid is accepted only for
//     entries up to where a branch's chain forked from that base
//     (chainCheck).
//   - PruneE2E folds the horizon's document and supplies it sealed as the
//     prune's snapshot (§8.6) under the epoch the newest content revision
//     of its chain sets (snapshotEpoch, §E.3.1).
//   - Blobs (§E.3.1, sealedblobs.go). Writes declare the blobs of the
//     resulting document in the sealed op (BlobIDs), so a write folds the
//     document even WithoutValidation; folds flag a revision whose list
//     differs from its decrypted document.
//   - Keyring administration (InitKeyring, AddReader, RotateEpoch) writes
//     the namespace's plaintext "keyring" resource (seal.KeyringV2,
//     §E.3.2), each entry wrapped in HPKE auth mode under the view's own
//     recipient key, the admin key its from names; RotateEpoch bumps
//     encryption.epoch in the same batch. MigrateKeyring wraps a keyring
//     stored in the format before v0.63 (seal.Keyring) again, which the
//     server refuses to have written now.
//
// Epoch keys come from keys added with AddKey, else (with a recipient
// private key) from POST /ns/{ns}/keys, which relays the keyring entries
// wrapped for the grant's enc, else from the namespace's own keyring
// resource (not one read through from a base: its keys are the base's).
// An entry opens only with the public key of the sender its from names
// (§E.3.2): the view knows its own recipient keys, those given with
// WithSenders or WithTrusted, and the client's (WithKeyringSenders,
// WithTrustedKeyringSenders), and skips entries from any other. It seals
// only under keys whose entry is from a sender it trusts to distribute
// keys (SealKey): with trusted senders named, those and its own keys;
// with none, every sender it knows. Reads open keys from any known sender.
// Writes seal under the current epoch, with the pad setting, both from the
// namespace document, or, for a writer limited to some resources that
// can't read it (§C.5), from what POST /ns/{ns}/keys names beside the keys
// (§E.2.3), which relays keys to such a grant when it carries enc.
//
// Padding (§E.2.2, §E.3.1). In a namespace with "encryption": { "pad":
// true } writes pad the plaintext of every sealed patch set (and prune
// snapshot) to its size bucket, uncompressed (seal.SealPatchSetPad). A
// fold flags a patch set that isn't padded when the namespace that sealed
// it padded at the time, like a failed validation. Turning pad on doesn't
// flag what was sealed before: the namespace log tells which configuration
// each revision was written under. A grant that can't read that log flags
// nothing for padding.
//
// Merge and rebase (§F.8) read a branch's changes as plaintext with
// OpenLog and write them under the target's keys with SealPatches.

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
)

// KeyringName is the reserved resource of an e2e namespace holding its
// keyring (§E.3.2).
const KeyringName = "keyring"

// E2E is a key-holding view of a Client for e2e namespaces. It is safe for
// concurrent use.
type E2E struct {
	c         *Client
	recipient *ecdh.PrivateKey
	extra     []*ecdh.PrivateKey // more recipients to unwrap with (WithRecipient)
	senders   []*ecdh.PublicKey  // keyring senders known besides its own keys (WithSenders)
	// trusted are the senders the view trusts to distribute keys it seals
	// under (WithTrusted), besides its own keys (§E.3.2).
	trusted    []*ecdh.PublicKey
	keys       *e2eKeys
	schemas    *e2eSchemas
	pads       *e2ePads
	forks      *e2eForks
	noValidate bool
}

// e2eForks caches, per branch and resource, the revisions its chain forked
// from in its local bases (chainCheck): a branch's at never changes.
type e2eForks struct {
	mu sync.Mutex
	m  map[string][]string
}

// e2ePads caches, per namespace, whether it padded when each of its
// revisions was written (from its namespace log, as of head).
type e2ePads struct {
	mu sync.Mutex
	m  map[string]*padHistory
}

type padHistory struct {
	head string
	now  bool            // the namespace pads as of head
	at   map[string]bool // revision id -> pad in force when it was written
}

type e2eKeys struct {
	mu sync.Mutex
	m  map[string][]byte // kid -> K_e
	// from is, per kid, where its key came from: the thumbprint of the
	// sender of the keyring entry it was unwrapped from, "" for an entry
	// without one (a keyring stored before v0.63), or fromSelf for a key
	// added directly (AddKey) or made by the view (§E.3.2).
	from map[string]string
}

// fromSelf marks a key that came from no keyring entry (e2eKeys.from).
const fromSelf = "*"

type e2eSchemas struct {
	v      *schema.Validator
	mu     sync.Mutex
	m      map[string]any  // schema revision path -> document, in its own namespace
	drafts map[string]any  // schema revision path -> document drafted in a branch (§6.1)
	branch map[string]bool // namespace -> is a branch
}

// E2E returns an e2e view of c. recipient is the private key whose public
// key the keyring (and the grant's enc) names; it may be nil when keys are
// added with AddKey.
func (c *Client) E2E(recipient *ecdh.PrivateKey) *E2E {
	return &E2E{c: c, recipient: recipient,
		keys:    &e2eKeys{m: map[string][]byte{}, from: map[string]string{}},
		schemas: &e2eSchemas{v: schema.NewValidator(), m: map[string]any{}, drafts: map[string]any{}, branch: map[string]bool{}},
		pads:    &e2ePads{m: map[string]*padHistory{}},
		forks:   &e2eForks{m: map[string][]string{}}}
}

// WithRecipient returns a view that also unwraps keys with priv, sharing
// the key cache. A merge between namespaces whose keyrings name different
// keys of the merger (§F.8) needs both.
func (x *E2E) WithRecipient(priv *ecdh.PrivateKey) *E2E {
	cp := *x
	if cp.recipient == nil {
		cp.recipient = priv
	} else {
		cp.extra = append(append([]*ecdh.PrivateKey(nil), x.extra...), priv)
	}
	return &cp
}

// WithSenders returns a view that also opens keyring entries wrapped by
// the admin keys pubs (§E.3.2), sharing the key cache. A keyring entry
// names its sender by thumbprint only, and HPKE auth mode needs the
// sender's public key to open it, so a reader learns its admins' keys out
// of band, as it learns whom it trusts to distribute keys. The view's own
// recipient keys are always known: an admin reads back what it wrapped.
func (x *E2E) WithSenders(pubs ...*ecdh.PublicKey) *E2E {
	cp := *x
	cp.senders = append(append([]*ecdh.PublicKey(nil), x.senders...), pubs...)
	return &cp
}

// WithKeyringSenders makes every E2E view of the client open keyring
// entries wrapped by the admin keys pubs (E2E.WithSenders): services
// reading e2e namespaces (derived.Keys) take them so.
func WithKeyringSenders(pubs ...*ecdh.PublicKey) Option {
	return func(c *Client) { c.senders = append(c.senders, pubs...) }
}

// WithTrusted returns a view that trusts the admin keys pubs to distribute
// keys (§E.3.2), sharing the key cache: it opens their keyring entries, as
// WithSenders, and seals under the keys they wrapped. Once a view or its
// client names any trusted sender, it seals only under keys from those,
// its own recipient keys and keys added directly (AddKey); reads still
// open keys from every known sender. A view that names none trusts every
// sender it knows: their public keys came out of band too.
func (x *E2E) WithTrusted(pubs ...*ecdh.PublicKey) *E2E {
	cp := *x
	cp.trusted = append(append([]*ecdh.PublicKey(nil), x.trusted...), pubs...)
	return &cp
}

// WithTrustedKeyringSenders makes every E2E view of the client trust the
// admin keys pubs to distribute keys (E2E.WithTrusted).
func WithTrustedKeyringSenders(pubs ...*ecdh.PublicKey) Option {
	return func(c *Client) { c.trusted = append(c.trusted, pubs...) }
}

// ErrUntrustedKey reports an epoch key the view may read with but won't
// seal under: its keyring entry's from names a sender the view doesn't
// trust to distribute keys, and anyone, the server included, can wrap a
// key to a thumbprint (§E.3.2).
var ErrUntrustedKey = errors.New("client: the key's keyring entry is from a sender this view doesn't trust to distribute keys (§E.3.2)")

// knownSenders lists the keyring senders the view opens entries from: its
// own recipient keys, then WithSenders', then the client's, then the
// trusted ones.
func (x *E2E) knownSenders() []*ecdh.PublicKey {
	var out []*ecdh.PublicKey
	for _, p := range x.recipients() {
		out = append(out, p.PublicKey())
	}
	out = append(out, x.senders...)
	out = append(out, x.c.senders...)
	out = append(out, x.trusted...)
	return append(out, x.c.trusted...)
}

// trustedFrom reports whether the view seals under a key whose keyring
// entry names from (e2eKeys.from) as its sender: its own recipient keys
// and keys added directly always; with trusted senders named (WithTrusted,
// WithTrustedKeyringSenders), those; with none, every known sender, and
// an entry without from, of a keyring stored before v0.63.
func (x *E2E) trustedFrom(from string) bool {
	if from == fromSelf {
		return true
	}
	for _, p := range x.recipients() {
		if seal.Thumbprint(p.PublicKey()) == from {
			return true
		}
	}
	trusted := append(append([]*ecdh.PublicKey(nil), x.trusted...), x.c.trusted...)
	if len(trusted) == 0 {
		if from == "" {
			return true
		}
		trusted = x.knownSenders()
	}
	for _, p := range trusted {
		if seal.Thumbprint(p) == from {
			return true
		}
	}
	return false
}

// recipients lists the view's private keys, primary first.
func (x *E2E) recipients() []*ecdh.PrivateKey {
	if x.recipient == nil {
		return x.extra
	}
	return append([]*ecdh.PrivateKey{x.recipient}, x.extra...)
}

// E2EKeys returns an e2e view of c that uses raw epoch keys, by kid
// "{ns}#{e}", and never fetches any.
func (c *Client) E2EKeys(keys map[string][]byte) *E2E {
	x := c.E2E(nil)
	for kid, k := range keys {
		x.AddKey(kid, k)
	}
	return x
}

// WithoutValidation returns a copy that doesn't validate documents before
// writing (reads still verify and flag).
func (x *E2E) WithoutValidation() *E2E {
	cp := *x
	cp.noValidate = true
	return &cp
}

// Client returns the underlying client.
func (x *E2E) Client() *Client { return x.c }

// PublicKey returns the public key of the view's own recipient key, the
// admin key the keyring entries it writes name as from (§E.3.2), or nil
// without one.
func (x *E2E) PublicKey() *ecdh.PublicKey {
	if x.recipient == nil {
		return nil
	}
	return x.recipient.PublicKey()
}

// AddKey caches the epoch key of kid "{ns}#{e}". A key added so is
// trusted for sealing: it came from the caller.
func (x *E2E) AddKey(kid string, key []byte) { x.addKey(kid, key, fromSelf) }

// addKey caches the epoch key of kid, unwrapped from a keyring entry from
// the sender from (e2eKeys.from).
func (x *E2E) addKey(kid string, key []byte, from string) {
	x.keys.mu.Lock()
	x.keys.m[kid] = append([]byte(nil), key...)
	x.keys.from[kid] = from
	x.keys.mu.Unlock()
}

// Key returns the epoch key of kid, fetching and unwrapping it if needed.
// It opens keys from every sender the view knows; SealKey is for sealing.
func (x *E2E) Key(ctx context.Context, kid string) ([]byte, error) {
	return x.keyVia(ctx, kid, "")
}

// SealKey is Key for a key the view seals under: its keyring entry must be
// from a sender the view trusts (trustedFrom, §E.3.2), or it is
// ErrUntrustedKey.
func (x *E2E) SealKey(ctx context.Context, kid string) ([]byte, error) {
	key, err := x.Key(ctx, kid)
	if err != nil {
		return nil, err
	}
	x.keys.mu.Lock()
	from := x.keys.from[kid]
	x.keys.mu.Unlock()
	if !x.trustedFrom(from) {
		return nil, fmt.Errorf("%w: %s from %s", ErrUntrustedKey, kid, from)
	}
	return key, nil
}

// resourceKey derives K_r of name in namespace ns from the epoch key K_e
// (§E.2.1): E3 patch sets and snapshots are sealed under it (§E.3.1).
func resourceKey(epochKey []byte, ns, name string) ([]byte, error) {
	return seal.ResourceKey(epochKey, ns, name)
}

// keyVia is Key for content read through namespace via: its relay is asked
// first, since a branch relays its base's keyring, and a remote branch's
// base (§G.5.2) isn't a namespace of this deployment at all.
func (x *E2E) keyVia(ctx context.Context, kid, via string) ([]byte, error) {
	x.keys.mu.Lock()
	k := x.keys.m[kid]
	x.keys.mu.Unlock()
	if k != nil {
		return k, nil
	}
	privs := x.recipients()
	if len(privs) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoKeys, kid)
	}
	ns, epoch, err := seal.ParseKid(kid)
	if err != nil {
		return nil, err
	}
	// The relays first (§E.2.3): they need a read grant with enc. A
	// fetch that failed for a reason asking again may mend (Transient),
	// with no key found otherwise, is that failure, not ErrNoKeys: the key
	// may be there (a service waiting for the namespace keeps waiting).
	var failed, unwrapErr error
	relays := []string{ns}
	if via != "" && via != ns {
		relays = []string{via, ns}
	}
	for _, relay := range relays {
		got, err := x.c.FetchKeys(ctx, relay, []int{epoch}, nil)
		if err != nil {
			if Transient(err) {
				failed = err
			}
			continue
		}
		for _, e := range got {
			if e.Kid != kid || e.Resource != "" {
				continue
			}
			key, from := e.Key, ""
			if key == nil {
				if key, err = unwrapRelayed(privs, e.Wrapped, x.knownSenders()); err != nil {
					// Not the key for us, or from a sender this view
					// doesn't know (anyone can wrap to a thumbprint,
					// §E.3.2): the other relay or the keyring may still
					// hold it.
					unwrapErr = fmt.Errorf("client: unwrapping %s: %w", kid, err)
					continue
				}
				from = e.Wrapped.From
			}
			x.addKey(kid, key, from)
			return key, nil
		}
	}
	// Then the keyring itself (a key holder may read it directly), if it
	// is the namespace's own: a branch without one reads its base's
	// through, whose entries name the base's keys, not "{branch}#{e}".
	kr, old, _, err := x.keyring(ctx, ns)
	switch {
	case err == nil && kr != nil:
		for _, priv := range privs {
			if key, err := kr.EpochKey(priv, kid, x.knownSenders()); err == nil {
				e, _ := kr.Entry(kid, seal.Thumbprint(priv.PublicKey()))
				x.addKey(kid, key, e.From)
				return key, nil
			}
		}
	case err == nil && old.NS == ns:
		for _, priv := range privs {
			if key, err := old.EpochKey(priv, epoch); err == nil {
				x.addKey(kid, key, "")
				return key, nil
			}
		}
	case Transient(err):
		failed = err
	}
	if failed != nil {
		return nil, fmt.Errorf("client: fetching the epoch key %s: %w", kid, failed)
	}
	if unwrapErr != nil {
		return nil, unwrapErr
	}
	return nil, fmt.Errorf("%w: %s", ErrNoKeys, kid)
}

// unwrapRelayed opens a K_e that /keys relays from a keyring (§E.3.2) with
// one of privs (seal.UnwrapRelayed): an entry with from in auth mode under
// the one of senders it names, one relayed from a keyring stored before
// v0.63 under the HPKE info of v0.63 or of that time.
func unwrapRelayed(privs []*ecdh.PrivateKey, w seal.WrappedKey, senders []*ecdh.PublicKey) ([]byte, error) {
	err := fmt.Errorf("client: no recipient key")
	for _, priv := range privs {
		var key []byte
		if key, err = seal.UnwrapRelayed(priv, w, senders); err == nil {
			return key, nil
		}
	}
	return nil, err
}

// EncryptionLevel returns a namespace's encryption.level ("" if none). A
// sealed namespace (E2) serves its document as a JWE; it is reported as
// "sealed" without decrypting it.
func (c *Client) EncryptionLevel(ctx context.Context, ns string) (string, error) {
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		return "", err
	}
	r, err := c.do(ctx, "GET", "/ns/"+ns+"/rev/"+h.ID, nil, nil)
	if err != nil {
		return "", err
	}
	if r.status != 200 {
		return "", r.apiError()
	}
	if isJOSE(r) {
		return "sealed", nil
	}
	enc, _ := r.obj()["encryption"].(map[string]any)
	lv, _ := enc["level"].(string)
	return lv, nil
}

// e2eConfig is what writes need from an e2e namespace document.
type e2eConfig struct {
	Config string // config revision id
	Epoch  int
	Base   string // the base namespace of a branch, "" otherwise
	Remote bool   // the base is in another deployment (§G.3)
	// Chain is a remote base's base.chain: its namespace and its bases as
	// of at (§G.3); nil if the document doesn't give it.
	Chain []string
	Pad   bool   // encryption.pad (§E.2.2)
	At    string // a branch's base.at, the base's namespace entry it forked at
}

func (x *E2E) config(ctx context.Context, ns string) (*e2eConfig, error) {
	h, err := x.c.NSHead(ctx, ns)
	if err != nil {
		return nil, err
	}
	d, err := x.c.NSDoc(ctx, ns, h.ID)
	if err != nil {
		return nil, err
	}
	enc, _ := d.Value["encryption"].(map[string]any)
	if lv, _ := enc["level"].(string); lv != "e2e" {
		return nil, fmt.Errorf("client: namespace %s is not e2e (encryption.level %q)", ns, lv)
	}
	out := &e2eConfig{Config: h.Config, Epoch: 1}
	if f, ok := enc["epoch"].(float64); ok {
		out.Epoch = int(f)
	}
	out.Pad, _ = enc["pad"].(bool)
	if b, ok := d.Value["base"].(map[string]any); ok {
		out.Base, _ = b["ns"].(string)
		out.At, _ = b["at"].(string)
		_, out.Remote = b["origin"]
		if arr, ok := b["chain"].([]any); ok && out.Remote {
			for _, x := range arr {
				if s, ok := x.(string); ok && ValidNSName(s) {
					out.Chain = append(out.Chain, s)
				}
			}
		}
	}
	return out, nil
}

// writeConfig is config for sealing: where the namespace document can't be
// read, as by a writer limited to some resources (§C.5), the current epoch
// and pad come from POST /ns/{ns}/keys instead (§E.2.3, §E.3.1). Bases are
// then unknown, which only reads need (chain), and keep needing the
// document. The server is outside the trust boundary at E3, so the epoch
// it names is raised to the newest one relayed to this grant: a server
// can't have it seal under an epoch older than one it holds a key for,
// though it can still withhold a newer one.
func (x *E2E) writeConfig(ctx context.Context, ns string) (*e2eConfig, error) {
	cfg, err := x.config(ctx, ns)
	if !nsUnreadable(err) {
		return cfg, err
	}
	a, kerr := x.c.FetchKeysAnswer(ctx, ns, nil, nil)
	switch {
	case IsNotOffered(kerr):
		return nil, fmt.Errorf("client: namespace %s is not e2e (it isn't sealed)", ns)
	case kerr != nil:
		return nil, fmt.Errorf("client: namespace %s: sealing needs the current epoch and pad, which neither its document (%w) nor /keys (%w) gives this grant", ns, err, kerr)
	case a.Level == "" || a.Epoch < 1:
		// A deployment before v0.51 names neither (§E.2.3).
		return nil, fmt.Errorf("client: namespace %s: sealing needs the current epoch and pad, which neither its document (%w) nor /keys gives this grant", ns, err)
	case a.Level != "e2e":
		return nil, fmt.Errorf("client: namespace %s is not e2e (encryption.level %q)", ns, a.Level)
	}
	epoch := a.Epoch
	for _, k := range a.Keys {
		if kns, e, perr := seal.ParseKid(k.Kid); perr == nil && kns == ns && e > epoch {
			epoch = e
		}
	}
	return &e2eConfig{Epoch: epoch, Pad: a.Pad}, nil
}

// --- writes ---------------------------------------------------------------

// SealPatches seals patches for a write to ns/name on parent ("" for
// genesis) under the resource's K_r of the namespace's current epoch
// (§E.3.1), padded if the namespace pads, and returns the patch set to
// send: [{"op":"sealed","value":"<JWE>"}]. The epoch key must be from a
// sender the view trusts (SealKey). Keep the bytes until the write is
// acknowledged: sealing again gives another id (§E.3.1).
func (x *E2E) SealPatches(ctx context.Context, ns, name, parent string, patches any) ([]byte, error) {
	return x.SealPatchesBlobs(ctx, ns, name, parent, patches, nil)
}

// SealPatchesBlobs is SealPatches with the declared blob list of the
// sealed op (§E.3.1): the ids of every blob the resulting document
// references (BlobIDs), omitted when empty.
func (x *E2E) SealPatchesBlobs(ctx context.Context, ns, name, parent string, patches any, blobs []string) ([]byte, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	v, err := ToValue(patches)
	if err != nil {
		return nil, err
	}
	cfg, err := x.writeConfig(ctx, ns)
	if err != nil {
		return nil, err
	}
	kid := seal.Kid(ns, cfg.Epoch)
	key, err := x.SealKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	kr, err := resourceKey(key, ns, name)
	if err != nil {
		return nil, err
	}
	body, err := seal.SealPatchSetPad(kr, kid, ns, name, parent, v, cfg.Pad)
	if err != nil || len(blobs) == 0 {
		return body, err
	}
	return seal.WithBlobs(body, blobs)
}

// send sends a sealed patch set, resending the same bytes after a
// transport failure or a retryable answer (an idempotent retry, §7.2).
func (x *E2E) send(ctx context.Context, write func(body []byte) (*WriteResult, error), body []byte) (*WriteResult, error) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		var w *WriteResult
		if w, err = write(body); err == nil {
			return w, nil
		}
		var ae *APIError
		if errors.As(err, &ae) && !Retryable(err) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, err
		}
	}
	return nil, err
}

// prepareWrite folds the document patches produce on base (a revision
// id, "" for genesis), checks it against its $schema and returns its
// declared blob list (§E.3.1). WithoutValidation skips the check, and a
// document it can't fold then declares no blobs.
func (x *E2E) prepareWrite(ctx context.Context, ns, name, base string, patches any) ([]string, error) {
	v, err := ToValue(patches)
	if err != nil {
		return nil, err
	}
	fail := func(err error) ([]string, error) {
		if x.noValidate {
			return nil, nil
		}
		return nil, err
	}
	// A create applies to the document null (§6.2 step 3).
	var doc any
	if base != "" {
		d, err := x.DocE2E(ctx, ns, name, base)
		if err != nil {
			return fail(err)
		}
		doc = d.Value
	}
	ops, err := patch.Parse(v)
	if err != nil {
		return fail(fmt.Errorf("client: e2e write %s/%s: %w", ns, name, err))
	}
	nd, _, err := patch.Apply(doc, true, ops, patch.Options{})
	if err != nil {
		return fail(fmt.Errorf("client: e2e write %s/%s: %w", ns, name, err))
	}
	if !x.noValidate {
		if msg, err := x.validate(ctx, ns, nd, false); err != nil {
			return nil, err
		} else if msg != "" {
			return nil, fmt.Errorf("client: e2e write %s/%s: the document doesn't validate against its $schema: %s", ns, name, msg)
		}
	}
	return BlobIDs(nd), nil
}

// CreateSealed creates ns/name with a sealed genesis patch set.
func (x *E2E) CreateSealed(ctx context.Context, ns, name string, patches any, opts ...WriteOption) (*WriteResult, error) {
	blobs, err := x.prepareWrite(ctx, ns, name, "", patches)
	if err != nil {
		return nil, err
	}
	body, err := x.SealPatchesBlobs(ctx, ns, name, "", patches, blobs)
	if err != nil {
		return nil, err
	}
	return x.send(ctx, func(b []byte) (*WriteResult, error) { return x.c.Create(ctx, ns, name, b, opts...) }, body)
}

// CreateDocSealed creates ns/name holding doc.
func (x *E2E) CreateDocSealed(ctx context.Context, ns, name string, doc any, opts ...WriteOption) (*WriteResult, error) {
	return x.CreateSealed(ctx, ns, name, GenesisPatches(doc), opts...)
}

// AppendSealed appends a sealed patch set on parent.
func (x *E2E) AppendSealed(ctx context.Context, ns, name, parent string, patches any, opts ...WriteOption) (*WriteResult, error) {
	if err := checkID("parent", parent); err != nil {
		return nil, err
	}
	blobs, err := x.prepareWrite(ctx, ns, name, parent, patches)
	if err != nil {
		return nil, err
	}
	body, err := x.SealPatchesBlobs(ctx, ns, name, parent, patches, blobs)
	if err != nil {
		return nil, err
	}
	return x.send(ctx, func(b []byte) (*WriteResult, error) { return x.c.Append(ctx, ns, name, parent, b, opts...) }, body)
}

// RestoreSealed restores a tombstoned resource whose head is tombstone:
// patches (sealed) apply to the last live document; nil or empty restores
// it unchanged with [] (§8.2), which needs no key.
func (x *E2E) RestoreSealed(ctx context.Context, ns, name, tombstone string, patches any, opts ...WriteOption) (*WriteResult, error) {
	if patches != nil {
		if v, err := ToValue(patches); err != nil {
			return nil, err
		} else if a, ok := v.([]any); ok && len(a) == 0 {
			patches = nil
		}
	}
	if patches == nil {
		return x.send(ctx, func([]byte) (*WriteResult, error) { return x.c.Restore(ctx, ns, name, tombstone, []any{}, opts...) }, nil)
	}
	h, err := x.c.Head(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	var blobs []string
	if h.State == Tombstoned && h.ID == tombstone {
		if blobs, err = x.prepareWrite(ctx, ns, name, h.Last, patches); err != nil {
			return nil, err
		}
	} else if !x.noValidate {
		return nil, fmt.Errorf("client: restore %s/%s: %s is not the head tombstone", ns, name, tombstone)
	}
	body, err := x.SealPatchesBlobs(ctx, ns, name, tombstone, patches, blobs)
	if err != nil {
		return nil, err
	}
	return x.send(ctx, func(b []byte) (*WriteResult, error) { return x.c.Restore(ctx, ns, name, tombstone, b, opts...) }, body)
}

// --- reads ----------------------------------------------------------------

// Flag is a revision a fold flagged: it didn't validate, its declared blob
// list or padding was wrong (still folded), or it didn't open or apply
// (folded as []). Its author, recorded by the server, is accountable
// (§E.3.2).
type Flag struct {
	ID      string
	Author  string
	Message string
}

// E2EDoc is a folded e2e document.
type E2EDoc struct {
	ID string // the revision asked for
	// Value is the document as of ID (§E.3.2): flagged revisions that
	// opened and applied are in it, those that didn't are folded as [].
	// ValidID is the last revision folded without a flag.
	Value   any
	ValidID string
	Flagged []Flag
	// Plain is set when the server served the document itself (the
	// keyring, or a namespace that isn't e2e).
	Plain bool

	// log is the range folded, after since, whose snapshot's kid is
	// sinceKid (PruneE2E's snapshot epoch, §E.3.1).
	log             []LogEntry
	since, sinceKid string
}

// LoadE2E reads the head and, if live, folds the document at it.
func (x *E2E) LoadE2E(ctx context.Context, ns, name string) (*Head, *E2EDoc, error) {
	h, err := x.c.Head(ctx, ns, name)
	if err != nil || h.State != Live {
		return h, nil, err
	}
	d, err := x.DocE2E(ctx, ns, name, h.ID)
	return h, d, err
}

// Moved is Client.Moved for an e2e namespace (§8.1, §11): it folds the
// document at h.Last, verifying its chain, and reads its $successor. The
// server is outside the trust boundary at E3, and its 410s there carry no
// successor, so one that h names is ignored: a move it made up would steer
// the client, and the edits it follows with, to a resource of its choice.
func (x *E2E) Moved(ctx context.Context, ns, name string, h *Head) (string, error) {
	if h == nil || h.State != Tombstoned {
		return "", nil
	}
	d, err := x.DocE2E(ctx, ns, name, h.Last)
	if err != nil {
		return "", err
	}
	return SuccessorOf(d.Value), nil
}

// DocE2E folds the document at revision id: it follows the X-E2E fold
// redirect, opens and verifies the log and folds it (see E2E).
func (x *E2E) DocE2E(ctx context.Context, ns, name, id string) (*E2EDoc, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	if err := checkID("revision", id); err != nil {
		return nil, err
	}
	path := "/r/" + ns + "/" + name + "/rev/" + id
	r, err := x.c.do(ctx, "GET", path, nil, nil)
	if err != nil {
		return nil, err
	}
	switch {
	case r.status == 200 && r.header.Get("X-E2E") == "snapshot":
		// A pruning horizon: its sealed snapshot is the document (§8.6).
		doc, kid, err := x.openSnapshot(ctx, ns, name, id, r, x.inChainOf(ctx, ns, name, id, nil))
		if err != nil {
			return nil, err
		}
		return &E2EDoc{ID: id, Value: doc, ValidID: id, since: id, sinceKid: kid}, nil
	case r.status == 200:
		d, err := x.c.Doc(ctx, ns, name, id)
		if err != nil {
			return nil, err
		}
		return &E2EDoc{ID: id, Value: d.Value, ValidID: id, Plain: true}, nil
	case r.status == 302 && r.header.Get("X-E2E") == "fold":
	default:
		return nil, r.apiError()
	}
	since := ""
	if u, err := url.Parse(r.header.Get("Location")); err == nil {
		since = u.Query().Get("since")
	}
	arr, err := x.foldLog(ctx, ns, name, id, since)
	if err != nil {
		var ae *APIError
		// A redirect cached before a prune may name a range that is gone
		// now: start again from the horizon.
		if h := Horizon(err); errors.As(err, &ae) && ae.Code == "pruned" && h != "" && h != since {
			since = h
			arr, err = x.foldLog(ctx, ns, name, id, since)
		}
		if err != nil {
			return nil, err
		}
	}
	return x.fold(ctx, ns, name, id, since, arr)
}

// foldLog fetches the log a fold reads, the range after since up to id,
// following its pages (§7.1). The range never holds since's snapshot: fold
// fetches that from /rev/{since}.
func (x *E2E) foldLog(ctx context.Context, ns, name, id, since string) ([]any, error) {
	if err := checkOptID("since", since); err != nil {
		return nil, err
	}
	arr := []any{}
	for cur := since; ; {
		next, err := x.c.logPage(ctx, "/r/"+ns+"/"+name+"/rev/"+id+"/log", cur, id, func(r *response, end string) (string, error) {
			page, ok := r.value().([]any)
			if !ok {
				return "", fmt.Errorf("client: %s: log is not an array", r.path)
			}
			arr = append(arr, page...)
			m, _ := arrAt(page, len(page)-1).(map[string]any)
			return str(m, "id"), nil
		})
		if err != nil {
			return nil, err
		}
		if next == "" {
			return arr, nil
		}
		cur = next
	}
}

// chain maps ns and its bases to their depth: 0 for ns, 1 for its base,
// and so on (a branch reads its base's ciphertext, whose patch sets and
// snapshots are bound to the base, §F.8). A remote base (§G.3) ends the
// walk: its namespaces are in another deployment, so they are listed in
// remote and not read here. They are the base's base.chain (the remote
// base and its own bases, as the branch's deployment followed them), or
// just the base's namespace without one. A remote branch keeps their names
// in pl.ns (§G.5.2).
func (x *E2E) chain(ctx context.Context, ns string) (depth map[string]int, remote map[string]bool, err error) {
	depth, remote = map[string]int{}, map[string]bool{}
	for cur, d := ns, 0; cur != ""; d++ {
		if _, seen := depth[cur]; seen {
			break
		}
		depth[cur] = d
		cfg, err := x.config(ctx, cur)
		if err != nil {
			return nil, nil, err
		}
		if cfg.Remote {
			names := cfg.Chain
			if len(names) == 0 {
				names = []string{cfg.Base}
			}
			for i, b := range names {
				if _, seen := depth[b]; !seen {
					depth[b], remote[b] = d+1+i, true
				}
			}
			break
		}
		cur = cfg.Base
	}
	return depth, remote, nil
}

// chainCheck checks, for the entries of one resource log of ns in order,
// whether each may be sealed under namespace kns: ns itself or one of its
// bases (read through, §F.8.1), and never a base deeper than an earlier
// entry's, since read-through content comes before a namespace's own
// writes. A base's namespace is accepted only for entries up to where the
// chain forked from that base (Addendum E Levels, §E.3.1): its head of the
// resource as of the branch's at, the fork, which /heads gives. Past the
// fork, every entry is the branch's own. A fork in a remote base, or one a
// reader without access to the base's /heads can't place, isn't checked.
type chainCheck struct {
	x      *E2E
	ctx    context.Context
	ns     string
	depth  map[string]int
	remote map[string]bool
	last   int

	// name is the resource whose log is checked ("" for no fork check);
	// since and ids are the range: what it starts after, and its ids.
	name  string
	since string
	ids   map[string]bool
	seen  []string // ids passed before the forks were loaded
	// forks[d] is the revision of name that the chain at depth d forked
	// from in the base at depth d+1, "" where that base had none; passed[d]
	// is set once the check is past it. loaded is set once they are known
	// (nil forks: not checked).
	forks  []string
	passed []bool
	loaded bool
}

func (x *E2E) inChain(ctx context.Context, ns string) *chainCheck {
	return &chainCheck{x: x, ctx: ctx, ns: ns, last: -1}
}

// inChainOf is inChain for the log of resource name after since ("" from
// its genesis), whose entries' ids are ids: base-sealed entries are
// accepted only up to the forks.
func (x *E2E) inChainOf(ctx context.Context, ns, name, since string, ids []string) *chainCheck {
	c := x.inChain(ctx, ns)
	c.name, c.since, c.ids = name, since, make(map[string]bool, len(ids))
	for _, id := range ids {
		c.ids[id] = true
	}
	return c
}

func (c *chainCheck) ok(kns string) (bool, error) {
	d := 0
	if kns != c.ns {
		if c.depth == nil {
			var err error
			if c.depth, c.remote, err = c.x.chain(c.ctx, c.ns); err != nil {
				return false, err
			}
		}
		var ok bool
		if d, ok = c.depth[kns]; !ok {
			return false, nil
		}
		if c.name != "" {
			if err := c.loadForks(); err != nil {
				return false, err
			}
			for j := 0; j < d && j < len(c.passed); j++ {
				if c.passed[j] {
					return false, nil
				}
			}
		}
	}
	if c.last >= 0 && d > c.last {
		return false, nil
	}
	c.last = d
	return true, nil
}

// at records that the check moved past entry id (any entry, a tombstone,
// a restore's [] or the snapshot the range starts from included).
func (c *chainCheck) at(id string) {
	if !c.loaded {
		c.seen = append(c.seen, id)
		return
	}
	for d, f := range c.forks {
		if f != "" && f == id {
			c.passed[d] = true
		}
	}
}

// loadForks finds the forks of the resource in ns's local bases (cached
// per view) and where the range stands to each.
func (c *chainCheck) loadForks() error {
	if c.loaded {
		return nil
	}
	forks, err := c.x.forksOf(c.ctx, c.ns, c.name)
	if err != nil {
		return err
	}
	c.loaded, c.forks, c.passed = true, forks, make([]bool, len(forks))
	for d, f := range forks {
		switch {
		case f == "":
			// The base had no revision of it: nothing is read through.
			c.passed[d] = true
		case c.since == "" || f == c.since || c.ids[f]:
			// Met in order (at), or the range lies before it.
		default:
			// The range starts after since, and doesn't hold the fork:
			// the fork comes later, or since lies past it.
			before, err := c.x.ancestor(c.ctx, c.ns, c.name, c.since, f)
			if err != nil {
				return err
			}
			c.passed[d] = !before
		}
	}
	for _, id := range c.seen {
		c.at(id)
	}
	c.seen = nil
	return nil
}

// forksOf returns, for ns and its local bases, the forks of resource name
// (chainCheck.forks), nil where they can't be had: ns isn't a branch, its
// base is remote, or this reader can't read a base's /heads.
func (x *E2E) forksOf(ctx context.Context, ns, name string) ([]string, error) {
	key := ns + "/" + name
	x.forks.mu.Lock()
	f, ok := x.forks.m[key]
	x.forks.mu.Unlock()
	if ok {
		return f, nil
	}
	var forks []string
	for cur, seen := ns, map[string]bool{}; !seen[cur]; {
		seen[cur] = true
		cfg, err := x.config(ctx, cur)
		if err != nil {
			return nil, err
		}
		if cfg.Base == "" || cfg.Remote || cfg.At == "" {
			break
		}
		fork, err := x.headAt(ctx, cfg.Base, cfg.At, name)
		if IsAuth(err) || IsNotFound(err) || IsGone(err) {
			forks = nil
			break
		}
		if err != nil {
			return nil, err
		}
		forks = append(forks, fork)
		cur = cfg.Base
	}
	x.forks.mu.Lock()
	x.forks.m[key] = forks
	x.forks.mu.Unlock()
	return forks, nil
}

// headAt returns the revision of name that ns's /heads lists as of nsID,
// its head or tombstone, read-through ones included; "" if it lists none
// or a purge. Pages start just before name, a plain bound (§7.4).
func (x *E2E) headAt(ctx context.Context, ns, nsID, name string) (string, error) {
	after := name
	if _, size := utf8.DecodeLastRuneInString(name); size > 0 {
		after = name[:len(name)-size]
	}
	for {
		items, next, err := x.c.HeadsPage(ctx, ns, nsID, after)
		if err != nil {
			return "", err
		}
		for _, it := range items {
			switch {
			case it.Resource == name && it.Kind != "purge":
				return it.Target, nil
			case it.Resource >= name:
				return "", nil
			}
		}
		if next == "" {
			return "", nil
		}
		after = next
	}
}

// ancestor reports whether revision a precedes revision b in the chain of
// ns/name: the server serves the range after a up to b only then.
func (x *E2E) ancestor(ctx context.Context, ns, name, a, b string) (bool, error) {
	_, _, err := x.c.LogPage(ctx, ns, name, b, a)
	var ae *APIError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500 && !Retryable(err):
		return false, nil
	}
	return false, err
}

// isRemote reports a remote base, whose configuration isn't readable here.
func (c *chainCheck) isRemote(kns string) bool { return c.remote[kns] }

// openSealed opens the sealed patch set of revision e of name. A non-empty
// flag says why the revision can't be folded: it isn't a sealed patch set,
// is sealed under a namespace nsOK refuses, or doesn't open or verify. A
// non-empty padFlag says it opened but isn't padded although the namespace
// that sealed it padded at the time (§E.2.2), which flags it but leaves it
// folded (§E.3.2). err is for failures that aren't the revision's fault
// (keys, transport).
func (x *E2E) openSealed(ctx context.Context, name string, e LogEntry, nsOK *chainCheck) (plain any, flag, padFlag string, err error) {
	jwe, ok := seal.SealedJWE(e.Patches)
	if !ok {
		return nil, "not a sealed patch set", "", nil
	}
	h, err := seal.ParseHeader(jwe)
	if err != nil {
		return nil, "sealed patch set: " + err.Error(), "", nil
	}
	kns, _, err := seal.ParseKid(h.Kid)
	if err != nil {
		return nil, "sealed patch set: " + err.Error(), "", nil
	}
	if ok, err := nsOK.ok(kns); err != nil {
		return nil, "", "", err
	} else if !ok {
		return nil, "sealed under another namespace's key " + h.Kid, "", nil
	}
	key, err := x.keyVia(ctx, h.Kid, nsOK.ns)
	if err != nil {
		return nil, "", "", err
	}
	plain, padded, err := openPatchSet(e.Patches, key, h.Kid, kns, name, e.Parent)
	if err != nil {
		return nil, "sealed patch set: " + err.Error(), "", nil
	}
	// A remote base's padding history isn't readable here (§G.5.2).
	if !padded && !nsOK.isRemote(kns) {
		if must, err := x.paddedAt(ctx, kns, e.ID); err != nil {
			return nil, "", "", err
		} else if must {
			return plain, "", "the sealed patch set isn't padded to its size bucket, but " + kns + " pads (§E.2.2)", nil
		}
	}
	return plain, "", "", nil
}

// openPatchSet opens a sealed patch set of name sealed under the epoch key
// K_e of kid in namespace kns: under the resource's K_r = HKDF(K_e, kns,
// name), kns being the pl.ns the open checks (§E.3.1), or failing that
// under K_e itself, which sealed E3 patch sets before v0.65 and whose
// ciphertext keeps its ids.
func openPatchSet(patchSet any, key []byte, kid, kns, name, parent string) (any, bool, error) {
	kr, err := resourceKey(key, kns, name)
	if err != nil {
		return nil, false, err
	}
	plain, padded, err := seal.OpenPatchSetPadded(patchSet, kr, kid, kns, name, parent)
	if err != nil {
		if p, pd, lerr := seal.OpenPatchSetPadded(patchSet, key, kid, kns, name, parent); lerr == nil {
			return p, pd, nil
		}
	}
	return plain, padded, err
}

// openSnapshotJWE opens a prune snapshot of revision h of name sealed under
// the epoch key K_e of kid in namespace kns: under K_r, then K_e, as
// openPatchSet.
func openSnapshotJWE(jwe string, key []byte, kid, kns, name, h string) (any, error) {
	kr, err := resourceKey(key, kns, name)
	if err != nil {
		return nil, err
	}
	doc, err := seal.OpenSnapshot(jwe, kr, kid, kns, name, h)
	if err != nil {
		if d, lerr := seal.OpenSnapshot(jwe, key, kid, kns, name, h); lerr == nil {
			return d, nil
		}
	}
	return doc, err
}

// paddedAt reports whether ns padded when revision id was written: the
// pad of the configuration in force at its entry in ns's log (§E.2.2), so
// a revision written while pad was on is judged so after pad is turned
// off. A revision the log doesn't list (yet) is judged by the current
// configuration.
func (x *E2E) paddedAt(ctx context.Context, ns, id string) (bool, error) {
	x.pads.mu.Lock()
	ph := x.pads.m[ns]
	x.pads.mu.Unlock()
	if ph != nil {
		if p, ok := ph.at[id]; ok {
			return p, nil
		}
	}
	h, err := x.c.NSHead(ctx, ns)
	if nsUnreadable(err) {
		// A writer limited to some resources (§C.5) can't tell which
		// configuration a revision was written under, so it flags
		// nothing: /keys gives only the current pad.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if ph == nil || ph.head != h.ID {
		if ph, err = x.padHistory(ctx, ns, h.ID, ph); err != nil {
			return false, err
		}
		x.pads.mu.Lock()
		x.pads.m[ns] = ph
		x.pads.mu.Unlock()
	}
	if p, ok := ph.at[id]; ok {
		return p, nil
	}
	return ph.now, nil
}

func padOf(doc map[string]any) bool {
	enc, _ := doc["encryption"].(map[string]any)
	p, _ := enc["pad"].(bool)
	return p
}

// padHistory reads ns's log up to head and records, for every revision it
// names, whether the namespace padded when it was written: the namespace
// document in force at its entry, which for a batch that changes the
// configuration is the one it produces (§E.2.2, §7.5). With prev, the
// history as of an earlier head, it reads only the log after that head,
// falling back to the whole log if prev's head isn't in its chain.
func (x *E2E) padHistory(ctx context.Context, ns, head string, prev *padHistory) (*padHistory, error) {
	d, err := x.c.NSDoc(ctx, ns, head)
	if err != nil {
		return nil, err
	}
	ph := &padHistory{head: head, now: padOf(d.Value), at: map[string]bool{}}
	cur := false
	var log []NSEntry
	if prev != nil {
		if log, err = x.c.NSLog(ctx, ns, head, prev.head); err == nil {
			for id, p := range prev.at {
				ph.at[id] = p
			}
			cur = prev.now
		}
	}
	if prev == nil || err != nil {
		if log, err = x.c.NSLog(ctx, ns, head, ""); err != nil {
			return nil, err
		}
	}
	var visit func(e NSEntry)
	visit = func(e NSEntry) {
		switch e.Kind {
		case "head":
			ph.at[e.Target] = cur
		case "batch":
			for _, s := range e.Entries {
				visit(s)
			}
		}
	}
	for _, e := range log {
		if e.Kind == "config" || (e.Kind == "batch" && len(e.Entries) > 0 && e.Entries[0].Kind == "config") {
			// The configuration the entry produces, before its items.
			d, err := x.c.NSDoc(ctx, ns, e.ID)
			if err != nil {
				return nil, err
			}
			cur = padOf(d.Value)
		}
		visit(e)
	}
	return ph, nil
}

// OpenLog opens the revisions of es, log entries of ns/name as Client.Log
// returns them, and returns copies whose Patches are the plaintext patch
// sets (a restore with [] stays []; tombstones and absent patch sets are
// unchanged). A revision that can't be opened (see openSealed), which a
// fold folds as [], gets no patches (HasPatches false) and its reason in
// flags, at the same index. One that opens but isn't padded as its
// namespace padded keeps its patches and no flag, since folds still apply
// it (§E.3.2); folds flag it. The ids stay those over ciphertext. Merge
// and rebase (§F.8) read branch changes this way. A leading entry with
// neither kind nor patch set (a horizon, as merge plans list one) is what
// the others follow, for placing the forks of a branch's chain
// (chainCheck).
func (x *E2E) OpenLog(ctx context.Context, ns, name string, es []LogEntry) (out []LogEntry, flags []string, err error) {
	since := ""
	if len(es) > 0 && es[0].Kind == "" && !es[0].HasPatches {
		since = es[0].ID
	}
	return x.openLog(ctx, ns, name, since, es)
}

// openLog is OpenLog for entries that follow since ("" for genesis).
func (x *E2E) openLog(ctx context.Context, ns, name, since string, es []LogEntry) (out []LogEntry, flags []string, err error) {
	ids := make([]string, len(es))
	for i, e := range es {
		ids[i] = e.ID
	}
	nsOK := x.inChainOf(ctx, ns, name, since, ids)
	out = make([]LogEntry, len(es))
	flags = make([]string, len(es))
	for i, e := range es {
		out[i] = e
		if e.Kind == "tombstone" || !e.HasPatches {
			nsOK.at(e.ID)
			continue
		}
		if a, ok := e.Patches.([]any); ok && len(a) == 0 {
			nsOK.at(e.ID)
			continue
		}
		plain, msg, _, err := x.openSealed(ctx, name, e, nsOK)
		nsOK.at(e.ID)
		if err != nil {
			return nil, nil, err
		}
		if msg != "" {
			out[i].Patches, out[i].HasPatches, flags[i] = nil, false, msg
			continue
		}
		out[i].Patches = plain
	}
	return out, flags, nil
}

// Validate checks doc against its $schema as writes do (§E.3.2): "" if it
// is valid or has none, else what is wrong. err is for a schema that
// couldn't be fetched.
func (x *E2E) Validate(ctx context.Context, doc any) (string, error) {
	if x.noValidate {
		return "", nil
	}
	return x.validate(ctx, "", doc, false)
}

// ValidateIn is Validate for a document written to namespace target,
// resolving $schema as the target's gate would (§6.1, §F.8.1): in a branch,
// a path its namespace can't resolve is looked up among drafts in that
// namespace's branches; elsewhere only in the schema namespaces themselves.
func (x *E2E) ValidateIn(ctx context.Context, target string, doc any) (string, error) {
	if x.noValidate {
		return "", nil
	}
	return x.validate(ctx, target, doc, false)
}

// snapshot fetches the sealed snapshot of the pruning horizon h of ns/name
// from /rev/{h}, where it is served instead of being a log entry (§7.1
// Paging, §8.6), and opens it.
func (x *E2E) snapshot(ctx context.Context, ns, name, h string, nsOK *chainCheck) (any, string, error) {
	r, err := x.c.do(ctx, "GET", "/r/"+ns+"/"+name+"/rev/"+h, nil, nil)
	if err != nil {
		return nil, "", err
	}
	if (r.status != 200 && r.status != 410) || r.header.Get("X-E2E") != "snapshot" {
		if r.status >= 400 {
			return nil, "", r.apiError()
		}
		return nil, "", fmt.Errorf("client: e2e log of %s/%s: /rev/%s doesn't serve the snapshot the fold starts from (status %d): %w", ns, name, h, r.status, seal.ErrMismatch)
	}
	return x.openSnapshot(ctx, ns, name, h, r, nsOK)
}

// openSnapshot opens the sealed snapshot of h that r, the answer of
// /rev/{h} with X-E2E: snapshot, serves: its body (200 application/jose),
// or for a tombstone horizon the "snapshot" member of its 410 body (the
// last live document). The snapshot is sealed under ns or one of its bases
// (a branch reads its base's ciphertext, §F.8) and bound to {name, h}.
func (x *E2E) openSnapshot(ctx context.Context, ns, name, h string, r *response, nsOK *chainCheck) (any, string, error) {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("client: e2e snapshot of %s/%s at %s: %s: %w", ns, name, h, fmt.Sprintf(format, args...), seal.ErrMismatch)
	}
	var jwe string
	if r.status == 410 {
		jwe = str(r.obj(), "snapshot")
	} else if isJOSE(r) {
		jwe = strings.TrimSpace(string(r.body))
	}
	if jwe == "" {
		return nil, "", bad("no sealed snapshot in the answer")
	}
	hd, err := seal.ParseHeader(jwe)
	if err != nil {
		return nil, "", bad("%v", err)
	}
	kns, _, err := seal.ParseKid(hd.Kid)
	if err != nil {
		return nil, "", bad("kid: %v", err)
	}
	if ok, err := nsOK.ok(kns); err != nil {
		return nil, "", err
	} else if !ok {
		return nil, "", bad("sealed under %s", hd.Kid)
	}
	key, err := x.keyVia(ctx, hd.Kid, ns)
	if err != nil {
		return nil, "", err
	}
	doc, err := openSnapshotJWE(jwe, key, hd.Kid, kns, name, h)
	if err != nil {
		return nil, "", fmt.Errorf("client: e2e snapshot of %s/%s at %s: %w", ns, name, h, err)
	}
	return doc, hd.Kid, nil
}

// fold verifies and folds a log answer ending at id and starting after
// since. A fold that starts at a pruning horizon (since set) starts from
// its snapshot, fetched from /rev/{since}.
//
// A revision that fails validation, whose declared blob list differs from
// its document, or that isn't padded as its namespace padded is flagged
// and still folded (§E.3.2, §E.3.1, §E.2.2). One whose patch set doesn't
// apply to its parent's document, a failing test included, is flagged and
// the fold goes on from that document as if it were []; so is one that
// doesn't open (another namespace's key, a pl or kid that doesn't match,
// a ciphertext that doesn't decrypt), which the spec leaves open (F-E7). A
// genesis applies to the document null (§6.2 step 3).
func (x *E2E) fold(ctx context.Context, ns, name, id, since string, arr []any) (*E2EDoc, error) {
	entries := make([]LogEntry, len(arr))
	ids := make([]string, len(arr))
	for i, v := range arr {
		e, err := parseLogEntry(v)
		if err != nil {
			return nil, err
		}
		entries[i], ids[i] = e, e.ID
	}
	nsOK := x.inChainOf(ctx, ns, name, since, ids)
	out := &E2EDoc{ID: id, log: entries, since: since}
	var doc any
	exists := false
	prev := ""
	bad := func(format string, args ...any) error {
		return fmt.Errorf("client: e2e log of %s/%s: %s: %w", ns, name, fmt.Sprintf(format, args...), seal.ErrMismatch)
	}
	if since != "" {
		var err error
		if doc, out.sinceKid, err = x.snapshot(ctx, ns, name, since, nsOK); err != nil {
			return nil, err
		}
		nsOK.at(since)
		exists, prev, out.ValidID = true, since, since
	}
	for _, e := range entries {
		if e.Parent != prev {
			return nil, bad("entry %s doesn't chain (parent %q, want %q)", e.ID, e.Parent, prev)
		}
		switch e.Kind {
		case "tombstone":
			want, err := ExpectedTombstone(e.Parent)
			if err != nil || want != e.ID {
				return nil, bad("tombstone %s has the wrong id", e.ID)
			}
			prev = e.ID
			nsOK.at(e.ID)
			continue
		case "rev":
		default:
			return nil, bad("entry %s of kind %q", e.ID, e.Kind)
		}
		if !e.HasPatches {
			return nil, bad("revision %s has no patch set", e.ID)
		}
		if want, err := ExpectedRevision(e.Parent, e.Patches); err != nil || want != e.ID {
			return nil, bad("revision %s has the wrong id", e.ID)
		}
		prev = e.ID
		if a, ok := e.Patches.([]any); ok && len(a) == 0 {
			// A restore with []: the last live document comes back.
			nsOK.at(e.ID)
			out.ValidID = e.ID
			continue
		}
		var flags []string
		flag := func(msg string) {
			flags = append(flags, msg)
			out.Flagged = append(out.Flagged, Flag{ID: e.ID, Author: e.Author, Message: msg})
		}
		plain, msg, padMsg, err := x.openSealed(ctx, name, e, nsOK)
		nsOK.at(e.ID)
		if err != nil {
			return nil, err
		}
		if msg != "" {
			flag(msg)
			continue
		}
		if padMsg != "" {
			flag(padMsg)
		}
		ops, err := patch.Parse(plain)
		if err != nil {
			flag("patch set: " + err.Error())
			continue
		}
		// A genesis applies to null (§6.2 step 3), whose document then
		// exists; a restore to the last live one.
		nd, _, err := patch.Apply(doc, true, ops, patch.Options{})
		if err != nil {
			flag("patch set doesn't apply: " + err.Error())
			continue
		}
		msg, err = x.validate(ctx, ns, nd, true)
		if err != nil {
			return nil, err
		}
		if msg != "" {
			flag("the document doesn't validate against its $schema: " + msg)
		}
		if _, declared, _ := seal.SealedOp(e.Patches); !sameBlobs(declared, BlobIDs(nd)) {
			flag("the declared blob list doesn't match the blobs the document references (§E.3.1)")
		}
		doc, exists = nd, true
		if len(flags) == 0 {
			out.ValidID = e.ID
		}
	}
	if prev != id {
		return nil, bad("the log ends at %s, not %s", prev, id)
	}
	if !exists {
		return nil, fmt.Errorf("client: e2e document %s/%s@%s: no valid revision", ns, name, id)
	}
	out.Value = doc
	return out, nil
}

func arrAt(a []any, i int) any {
	if i < len(a) {
		return a[i]
	}
	return nil
}

// errSchemaLoad wraps a failure to fetch a schema that isn't the schema's
// fault (transport, server errors): it fails the read instead of flagging.
type errSchemaLoad struct{ err error }

func (e *errSchemaLoad) Error() string { return e.err.Error() }
func (e *errSchemaLoad) Unwrap() error { return e.err }

// validate checks doc against its $schema (§6.1 forms), fetching schemas
// through the client. It returns a message for an invalid document, or an
// error when a schema couldn't be fetched. stored is for a revision a fold
// re-validates, which is held to the rules it was written under (§6.1):
// Legacy, until revisions keep their markers, so a schema document an
// earlier version accepted still folds.
func (x *E2E) validate(ctx context.Context, target string, doc any, stored bool) (string, error) {
	m, ok := doc.(map[string]any)
	if !ok {
		return "", nil
	}
	sv, has := m["$schema"]
	if !has {
		return "", nil
	}
	drafts := false
	if target != "" {
		x.schemas.mu.Lock()
		b, known := x.schemas.branch[target]
		x.schemas.mu.Unlock()
		if !known {
			// A namespace document the client can't read counts as not a
			// branch: paths then resolve only in their own namespaces.
			var err error
			if b, err = x.c.IsBranch(ctx, target); err == nil {
				x.schemas.mu.Lock()
				x.schemas.branch[target] = b
				x.schemas.mu.Unlock()
			}
		}
		drafts = b
	}
	load := func(ref schema.Ref) (any, error) {
		x.schemas.mu.Lock()
		d, ok := x.schemas.m[ref.Path()]
		if !ok && drafts {
			d, ok = x.schemas.drafts[ref.Path()]
		}
		x.schemas.mu.Unlock()
		if ok {
			return d, nil
		}
		r, err := x.c.ResolveSchema(ctx, ref, ResolveOptions{Drafts: drafts, For: target})
		if err != nil {
			if IsNotFound(err) || IsGone(err) || IsAuth(err) {
				return nil, schema.ErrUnavailable
			}
			return nil, &errSchemaLoad{err}
		}
		x.schemas.mu.Lock()
		if r.NS == ref.NS {
			x.schemas.m[ref.Path()] = r.Doc.Value
		} else {
			x.schemas.drafts[ref.Path()] = r.Doc.Value
		}
		x.schemas.mu.Unlock()
		return r.Doc.Value, nil
	}
	// The validator keeps compiled schemas, so whether each revision of the
	// closure resolves for this target is checked first.
	if s, _ := sv.(string); s != "" {
		if r, ok := schema.ParseRef(s); ok {
			seen := map[string]bool{}
			queue := []schema.Ref{r}
			for len(queue) > 0 {
				r := queue[0]
				queue = queue[1:]
				if seen[r.Path()] {
					continue
				}
				seen[r.Path()] = true
				d, err := load(r)
				if err != nil {
					var le *errSchemaLoad
					if errors.As(err, &le) {
						return "", le.err
					}
					return fmt.Sprintf("%s: %v", r.Path(), err), nil
				}
				queue = append(queue, schema.Refs(d)...)
			}
		}
	}
	var err error
	if stored {
		err = x.schemas.v.ValidateRules(doc, load, schema.Legacy)
	} else {
		err = x.schemas.v.Validate(doc, load)
	}
	if err == nil {
		return "", nil
	}
	var le *errSchemaLoad
	if errors.As(err, &le) {
		return "", le.err
	}
	return err.Error(), nil
}

// --- prune ----------------------------------------------------------------

// PruneE2E prunes ns/name below horizon (§8.6): it folds the horizon's
// document (for a tombstone horizon, which must be the head, the last live
// document), seals it as the snapshot and sends the prune. If the server
// moves the horizon down to a protected revision, it seals for that one
// and tries once more. The namespace needs an archive destination.
func (x *E2E) PruneE2E(ctx context.Context, ns, name, horizon string) (*PruneResult, error) {
	res, err := x.prune(ctx, ns, name, horizon)
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == 422 {
		if h := ae.Horizon(); h != "" && h != horizon {
			return x.prune(ctx, ns, name, h)
		}
	}
	return res, err
}

func (x *E2E) prune(ctx context.Context, ns, name, horizon string) (*PruneResult, error) {
	if err := checkID("horizon", horizon); err != nil {
		return nil, err
	}
	at := horizon
	h, err := x.c.Head(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	if h.State == Tombstoned && h.ID == horizon {
		at = h.Last
	}
	d, err := x.DocE2E(ctx, ns, name, at)
	if err != nil {
		return nil, err
	}
	cfg, err := x.writeConfig(ctx, ns)
	if err != nil {
		return nil, err
	}
	kid := seal.Kid(ns, snapshotEpoch(ns, cfg.Epoch, d))
	key, err := x.SealKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	kr, err := resourceKey(key, ns, name)
	if err != nil {
		return nil, err
	}
	snap, err := seal.SealSnapshotPad(kr, kid, ns, name, horizon, d.Value, cfg.Pad)
	if err != nil {
		return nil, err
	}
	// The snapshot needs no declared list: the server keeps the list of
	// the horizon's revision (§8.6, §E.3.1).
	return x.c.Prune(ctx, ns, name, PruneRequest{Horizon: horizon, Snapshot: snap})
}

// snapshotEpoch is the epoch a prune's snapshot of the document d folds is
// sealed under (§E.3.1), as the server checks it: set by the newest
// revision of the range d folded that isn't a tombstone and whose patch
// set isn't [], the epoch of its sealed op where the op is ns's own, not a
// base's, and otherwise current, ns's epoch in force. Where the range
// holds no such revision, the snapshot the fold started from stands for
// those below it, its epoch counting where its kid names ns (F-E2). Content
// from before a raise to e2e from sealed is P35's to fold; the rest from
// before a raise is plaintext, and takes current.
func snapshotEpoch(ns string, current int, d *E2EDoc) int {
	for i := len(d.log) - 1; i >= 0; i-- {
		e := d.log[i]
		if e.Kind == "tombstone" || !e.HasPatches {
			continue
		}
		if a, ok := e.Patches.([]any); ok && len(a) == 0 {
			continue
		}
		if jwe, ok := seal.SealedJWE(e.Patches); ok {
			if h, err := seal.ParseHeader(jwe); err == nil {
				if kns, ep, err := seal.ParseKid(h.Kid); err == nil && kns == ns {
					return ep
				}
			}
		}
		return current
	}
	if kns, ep, err := seal.ParseKid(d.sinceKid); err == nil && kns == ns && d.since != "" {
		return ep
	}
	return current
}

// --- keyring administration -------------------------------------------------

// ErrLegacyKeyring reports a keyring resource stored in the format before
// v0.63 (seal.Keyring), which servers no longer take as the keyring: a
// key holder wraps it again with MigrateKeyring.
var ErrLegacyKeyring = errors.New("client: the keyring is in the format before v0.63; wrap it again with MigrateKeyring")

// keyring reads the keyring resource of ns as ns sees it (its base's, read
// through, in a branch without one): the keyring document (§E.3.2), or
// failing that one in the format before v0.63 (old), and its head.
func (x *E2E) keyring(ctx context.Context, ns string) (kr *seal.KeyringV2, old *seal.Keyring, head string, err error) {
	h, d, err := x.c.Load(ctx, ns, KeyringName)
	if err != nil {
		return nil, nil, "", err
	}
	if h.State != Live {
		return nil, nil, "", &APIError{Status: 404, Code: "not_found", Method: "GET", Path: "/r/" + ns + "/" + KeyringName}
	}
	if kr, err = seal.ParseKeyringV2(d.Value); err == nil {
		return kr, nil, h.ID, nil
	}
	if old, lerr := seal.ParseKeyring(d.Value); lerr == nil {
		return nil, old, h.ID, nil
	}
	return nil, nil, "", err
}

// Keyring reads the keyring resource of ns (§E.3.2) as ns sees it and
// returns it with its head. One stored in the format before v0.63 is
// ErrLegacyKeyring (LegacyKeyring reads it).
func (x *E2E) Keyring(ctx context.Context, ns string) (*seal.KeyringV2, string, error) {
	kr, _, head, err := x.keyring(ctx, ns)
	if err == nil && kr == nil {
		return nil, "", ErrLegacyKeyring
	}
	return kr, head, err
}

// LegacyKeyring reads a keyring resource of ns stored in the format before
// v0.63 (seal.Keyring), to migrate it, and returns it with its head.
func (x *E2E) LegacyKeyring(ctx context.Context, ns string) (*seal.Keyring, string, error) {
	_, old, head, err := x.keyring(ctx, ns)
	if err == nil && old == nil {
		return nil, "", fmt.Errorf("client: the keyring of %s is not in the format before v0.63", ns)
	}
	return old, head, err
}

// KeyringReaders returns the public keys among those the view knows (its
// own recipient keys and senders, WithSenders) for which kr holds the key
// of its newest epoch, from a sender the view knows. A keyring names its
// recipients by thumbprint only, so a reader whose public key the view
// doesn't know can't be wrapped for again, and an entry from an unknown
// sender is not taken as a reader at all: anyone can wrap to a thumbprint
// (§E.3.2). Rewrapping for a new namespace (a successor's keyring, §F.8)
// starts from these.
func (x *E2E) KeyringReaders(kr *seal.KeyringV2) []*ecdh.PublicKey {
	newest, kid := -1, ""
	for _, e := range kr.Entries {
		if _, ep, err := seal.ParseKid(e.Kid); err == nil && ep > newest {
			newest, kid = ep, e.Kid
		}
	}
	from := map[string]bool{}
	for _, s := range x.knownSenders() {
		from[seal.Thumbprint(s)] = true
	}
	var out []*ecdh.PublicKey
	seen := map[string]bool{}
	for _, p := range x.knownSenders() {
		tp := seal.Thumbprint(p)
		if e, ok := kr.Entry(kid, tp); ok && from[e.From] && !seen[tp] {
			seen[tp] = true
			out = append(out, p)
		}
	}
	return out
}

// admin is the key that wraps the keyring entries the view writes, in
// HPKE auth mode: its own recipient key, which their from names (§E.3.2).
func (x *E2E) admin() (*ecdh.PrivateKey, error) {
	if x.recipient == nil {
		return nil, fmt.Errorf("client: keyring administration needs the view's recipient key, which wraps the entries (§E.3.2)")
	}
	return x.recipient, nil
}

// withSelf adds the view's own recipient to readers, once each.
func (x *E2E) withSelf(readers []*ecdh.PublicKey) []*ecdh.PublicKey {
	seen := map[string]bool{}
	var out []*ecdh.PublicKey
	if x.recipient != nil {
		readers = append([]*ecdh.PublicKey{x.recipient.PublicKey()}, readers...)
	}
	for _, r := range readers {
		if tp := seal.Thumbprint(r); !seen[tp] {
			seen[tp] = true
			out = append(out, r)
		}
	}
	return out
}

func replaceRoot(v any) []any {
	return []any{map[string]any{"op": "replace", "path": "", "value": v}}
}

// InitKeyring creates the keyring of ns: a fresh key for the current epoch,
// wrapped for readers and for the view's own recipient, which wraps them
// (auth mode, §E.3.2). In a branch that reads its base's keyring through,
// it replaces it with the branch's own (a first write on the foreign
// parent, §7.6).
func (x *E2E) InitKeyring(ctx context.Context, ns string, readers ...*ecdh.PublicKey) (*WriteResult, error) {
	admin, err := x.admin()
	if err != nil {
		return nil, err
	}
	cfg, err := x.config(ctx, ns)
	if err != nil {
		return nil, err
	}
	key := seal.NewKey()
	kr, err := seal.BuildKeyringV2(admin, ns, cfg.Epoch, key, x.withSelf(readers))
	if err != nil {
		return nil, err
	}
	var w *WriteResult
	cur, old, head, err := x.keyring(ctx, ns)
	switch {
	case err == nil && (cur != nil && cur.Current(ns) > 0 || old != nil && old.NS == ns):
		return nil, fmt.Errorf("client: namespace %s already has a keyring", ns)
	case err == nil:
		w, err = x.c.Append(ctx, ns, KeyringName, head, replaceRoot(kr.Value()))
	case IsNotFound(err):
		w, err = x.c.CreateDoc(ctx, ns, KeyringName, kr.Value())
	}
	if err != nil {
		return nil, err
	}
	x.AddKey(seal.Kid(ns, cfg.Epoch), key)
	return w, nil
}

// AddReader wraps the current epoch's key for reader (§E.3.2: adding a
// reader) and, with history, every older epoch of the keyring the view
// can open, in auth mode under the view's own recipient key.
func (x *E2E) AddReader(ctx context.Context, ns string, reader *ecdh.PublicKey, history bool) (*WriteResult, error) {
	admin, err := x.admin()
	if err != nil {
		return nil, err
	}
	kr, head, err := x.Keyring(ctx, ns)
	if err != nil {
		return nil, err
	}
	cur := kr.Current(ns)
	if cur == 0 {
		return nil, fmt.Errorf("client: the keyring of %s holds no key of it", ns)
	}
	for _, e := range kr.Epochs(ns) {
		if e != cur && !history {
			continue
		}
		// Wrapping is distributing: only keys from a sender the view
		// trusts (§E.3.2), so an injected entry isn't passed on.
		key, err := x.SealKey(ctx, seal.Kid(ns, e))
		if err != nil {
			if e == cur {
				return nil, err
			}
			continue
		}
		if err := kr.Add(admin, reader, seal.Kid(ns, e), key); err != nil {
			return nil, err
		}
	}
	return x.c.Append(ctx, ns, KeyringName, head, replaceRoot(kr.Value()))
}

// RotateEpoch starts a new epoch (§E.2.4, §E.3.2: revocation): a fresh key
// wrapped for exactly readers and the view's own recipient, written to the
// keyring together with encryption.epoch + 1 in one batch. It needs a grant
// chained to a * key (§7.4) and returns the new epoch.
func (x *E2E) RotateEpoch(ctx context.Context, ns string, readers ...*ecdh.PublicKey) (int, error) {
	admin, err := x.admin()
	if err != nil {
		return 0, err
	}
	kr, head, err := x.Keyring(ctx, ns)
	if err != nil {
		return 0, err
	}
	cfg, err := x.config(ctx, ns)
	if err != nil {
		return 0, err
	}
	if cur := kr.Current(ns); cur != cfg.Epoch {
		return 0, fmt.Errorf("client: the keyring of %s is at epoch %d but encryption.epoch is %d", ns, cur, cfg.Epoch)
	}
	key := seal.NewKey()
	e := cfg.Epoch + 1
	for _, r := range x.withSelf(readers) {
		if err := kr.Add(admin, r, seal.Kid(ns, e), key); err != nil {
			return 0, err
		}
	}
	_, err = x.c.Batch(ctx, ns, BatchRequest{
		Config: &BatchConfig{IfMatch: cfg.Config, Patches: []any{map[string]any{"op": "add", "path": "/encryption/epoch", "value": e}}},
		Items:  []BatchItem{{Resource: KeyringName, IfMatch: head, Steps: []Step{PatchStep(replaceRoot(kr.Value()))}}},
	}, false)
	if err != nil {
		return 0, err
	}
	x.AddKey(seal.Kid(ns, e), key)
	return e, nil
}

// MigrateKeyring wraps the keyring of ns stored in the format before v0.63
// again as the keyring document (§E.3.2, seal.MigrateKeyring): every
// epoch's key, which the view opens from its own entry, is wrapped in
// auth mode under the view's recipient key for the readers given for that
// epoch, and for the view itself. readers must name every epoch the old
// keyring holds, and comes from the caller, out of band: the stored
// recipient lists are untrusted (anyone could write them, and a reader
// left out of a rotation must not get its key now). It returns the write.
//
// On a keyring already in the new format it puts back the epochs that a
// migration left out (MigrateKeyringOpenable) from the newest earlier
// revision in the old format (MigrationSource), which readers must name
// then; with none left out, it writes nothing and returns nil.
func (x *E2E) MigrateKeyring(ctx context.Context, ns string, readers map[int][]*ecdh.PublicKey) (*WriteResult, error) {
	w, _, err := x.migrateKeyring(ctx, ns, readers, false)
	return w, err
}

// MigrateKeyringOpenable is MigrateKeyring for a key holder that can't open
// every epoch of the old keyring, such as a reader added at a later epoch,
// which in v0.55 could rotate: revoking means rotating the epoch (§E.3.2),
// and RotateEpoch needs the keyring in the new format. It wraps again the
// epochs of readers the view opens, which must include the old keyring's
// newest, and leaves out the others, which it returns: their keys are
// then in the keyring's history only, not in the keyring /keys relays,
// until a holder of them puts them back with MigrateKeyring.
func (x *E2E) MigrateKeyringOpenable(ctx context.Context, ns string, readers map[int][]*ecdh.PublicKey) (*WriteResult, []int, error) {
	return x.migrateKeyring(ctx, ns, readers, true)
}

// MigrationSource returns the keyring of ns in the format before v0.63 that
// MigrateKeyring wraps again, and the epochs of it to wrap, ascending: the
// keyring itself and all its epochs, or, when it is already in the new
// format, its newest earlier revision in the old format and the epochs the
// keyring lacks.
func (x *E2E) MigrationSource(ctx context.Context, ns string) (old *seal.Keyring, epochs []int, err error) {
	old, _, epochs, _, err = x.migrationSource(ctx, ns)
	return old, epochs, err
}

// migrationSource is MigrationSource, with the keyring document to wrap
// the epochs into (a new one, or the keyring as it is) and its head.
func (x *E2E) migrationSource(ctx context.Context, ns string) (old *seal.Keyring, dst *seal.KeyringV2, epochs []int, head string, err error) {
	cur, old, head, err := x.keyring(ctx, ns)
	if err != nil {
		return nil, nil, nil, "", err
	}
	have := map[int]bool{}
	switch {
	case old != nil && old.NS != ns:
		return nil, nil, nil, "", fmt.Errorf("client: %s reads the keyring of %s through; migrate it there", ns, old.NS)
	case old != nil:
		dst = &seal.KeyringV2{}
	case cur.Current(ns) == 0:
		return nil, nil, nil, "", fmt.Errorf("client: %s reads its base's keyring through; it has none of its own to migrate", ns)
	default:
		dst = cur
		for _, e := range cur.Epochs(ns) {
			have[e] = true
		}
		es, err := x.c.Log(ctx, ns, KeyringName, head, "")
		if err != nil {
			return nil, nil, nil, "", err
		}
		for i := len(es) - 1; i >= 0 && old == nil; i-- {
			if es[i].Kind != "rev" || es[i].ID == head {
				continue
			}
			d, err := x.c.Doc(ctx, ns, KeyringName, es[i].ID)
			if err != nil {
				return nil, nil, nil, "", err
			}
			if k, err := seal.ParseKeyring(d.Value); err == nil && k.NS == ns {
				old = k
			}
		}
		if old == nil {
			return nil, nil, nil, "", fmt.Errorf("client: the keyring of %s is not in the format before v0.63, and has no earlier revision in it", ns)
		}
	}
	for e := range old.Epochs {
		if !have[e] {
			epochs = append(epochs, e)
		}
	}
	sort.Ints(epochs)
	return old, dst, epochs, head, nil
}

// migrateKeyring is MigrateKeyring, leaving out with skip the epochs the
// view can't open (MigrateKeyringOpenable).
func (x *E2E) migrateKeyring(ctx context.Context, ns string, readers map[int][]*ecdh.PublicKey, skip bool) (*WriteResult, []int, error) {
	admin, err := x.admin()
	if err != nil {
		return nil, nil, err
	}
	old, kr, epochs, head, err := x.migrationSource(ctx, ns)
	if err != nil {
		return nil, nil, err
	}
	fresh := len(kr.Entries) == 0
	for e := range readers {
		if _, ok := old.Epochs[e]; !ok {
			return nil, nil, fmt.Errorf("client: migrating the keyring of %s: readers given for epoch %d, which it doesn't hold", ns, e)
		}
	}
	var left []int
	wrapped := 0
	for _, e := range epochs {
		rs, named := readers[e]
		var key []byte
		if named {
			for _, priv := range x.recipients() {
				if key, err = old.EpochKey(priv, e); err == nil {
					break
				}
			}
		}
		if key == nil {
			switch {
			case skip:
				left = append(left, e)
				continue
			case !named:
				return nil, nil, fmt.Errorf("client: migrating the keyring of %s: no readers given for epoch %d", ns, e)
			default:
				return nil, nil, fmt.Errorf("client: migrating the keyring of %s: epoch %d: %w", ns, e, err)
			}
		}
		for _, r := range x.withSelf(rs) {
			if err := kr.Add(admin, r, seal.Kid(ns, e), key); err != nil {
				return nil, nil, fmt.Errorf("client: migrating the keyring of %s: epoch %d: %w", ns, e, err)
			}
		}
		wrapped++
	}
	if fresh && slices.Contains(left, old.Current) {
		return nil, left, fmt.Errorf("client: migrating the keyring of %s: the view can't open its newest epoch %d, which writes and rotations need; a holder of it migrates", ns, old.Current)
	}
	if wrapped == 0 {
		return nil, left, nil
	}
	w, err := x.c.Append(ctx, ns, KeyringName, head, replaceRoot(kr.Value()))
	if err != nil {
		return nil, nil, err
	}
	return w, left, nil
}
