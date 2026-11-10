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
//   - Reads (DocE2E, LoadE2E) ask /r/{ns}/{name}/rev/{id}. The server never
//     folds (§7.1): it answers a prune's stored snapshot, 200
//     application/jose, which is the document, or 404 not_offered naming
//     the resource's horizon, and last, the parent of a tombstone horizon.
//     The reader folds the log up to id from last, else horizon, else from
//     genesis: /rev/{start} serves start's snapshot (never the log, §7.1
//     Paging, §8.6), and /rev/{id}/log?since={start} the range. It opens
//     every sealed patch set (checking kid, pl {ns, name, parent}, the id
//     chain and each id over the ciphertext) and verifies every
//     intermediate document that has a $schema. Patch sets and snapshots
//     open under K_r only, bound to pl exactly (§E.2.1, §E.3.1); nothing
//     sealed under K_e or in an earlier draft's form opens. A revision that
//     doesn't validate, declares the wrong blobs or isn't padded is flagged
//     with its author and still folded; one that doesn't open or apply is
//     flagged and folded as [] (§E.3.2). A base's namespace in pl and kid is
//     accepted only for entries up to where a branch's chain forked from
//     that base (chainCheck).
//   - PruneE2E folds the horizon's document (at a tombstone, the last live
//     one, its parent's) and supplies it sealed as the prune's snapshot
//     (§8.6), bound to that revision, under the epoch the newest content
//     revision of its chain sets (snapshotEpoch, §E.3.1).
//   - The message bound (§E.2.1): a view counts the sealings under each
//     resource's K_r of an epoch, refuses one past the bound
//     (ErrSealBound) and reports rotation due (SealStatus).
//   - Blobs (§E.3.1, sealedblobs.go). Writes declare the blobs of the
//     resulting document in the sealed op (BlobIDs), so a write folds the
//     document even WithoutValidation; folds flag a revision whose list
//     differs from its decrypted document.
//   - Keyring administration (InitKeyring, AddReader, RotateEpoch) writes
//     the namespace's plaintext "keyring" resource (seal.KeyringV2,
//     §E.3.2), each entry wrapped in HPKE auth mode under the view's own
//     recipient key, the admin key its from names; RotateEpoch bumps
//     encryption.epoch in the same batch. A keyring in the format before
//     v0.63 (seal.Keyring) isn't read: a key holder wraps it again with
//     the v0.26.1 client before upgrading.
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
// with none, every sender it knows. Where the first key found isn't
// trusted, SealKey looks on for an entry that is. Reads open keys from any
// known sender. A key without a sender, which /keys relays in the clear or
// in base mode as at E2, is neither opened with nor sealed under: at E3
// the server relays only keyring entries (§E.3.2), and could have wrapped
// such a key itself. A keyring in the format before v0.63 isn't read at
// all (Keyring).
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
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/middle-management/patchlog/internal/jsonv"
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
	seals      *e2eSeals
	noValidate bool
	// sealBound and sealMargin are the message bound this view keeps each
	// K_r within, and how far below it rotation is due (WithSealBound,
	// §E.2.1); 0 for the defaults.
	sealBound, sealMargin int64
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
	// sender of the keyring entry it was unwrapped from, or fromSelf for a
	// key added directly (AddKey) or made by the view (§E.3.2).
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
	// rules and draftRules are the markers the server served m's and
	// drafts' revisions with (Doc.Rules), metadata only since v0.74: every
	// revision compiles under this version's rules, as the core compiles
	// it (§6.1).
	rules, draftRules map[string]schema.Rules
}

func newE2ESchemas() *e2eSchemas {
	return &e2eSchemas{v: schema.NewValidator(), m: map[string]any{}, drafts: map[string]any{}, branch: map[string]bool{},
		rules: map[string]schema.Rules{}, draftRules: map[string]schema.Rules{}}
}

// E2E returns an e2e view of c. recipient is the private key whose public
// key the keyring (and the grant's enc) names; it may be nil when keys are
// added with AddKey.
func (c *Client) E2E(recipient *ecdh.PrivateKey) *E2E {
	return &E2E{c: c, recipient: recipient,
		keys:    &e2eKeys{m: map[string][]byte{}, from: map[string]string{}},
		schemas: newE2ESchemas(),
		pads:    &e2ePads{m: map[string]*padHistory{}},
		forks:   &e2eForks{m: map[string][]string{}},
		seals:   &e2eSeals{m: map[string]*sealCount{}}}
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
// WithTrustedKeyringSenders), those; with none, every known sender, whose
// public key came out of band too. A key without a sender ("") never
// (findKey takes none): anyone, the server included, can have wrapped it
// (§E.3.2).
func (x *E2E) trustedFrom(from string) bool {
	if from == fromSelf {
		return true
	}
	if from == "" {
		return false
	}
	for _, p := range x.recipients() {
		if seal.Thumbprint(p.PublicKey()) == from {
			return true
		}
	}
	trusted := append(append([]*ecdh.PublicKey(nil), x.trusted...), x.c.trusted...)
	if len(trusted) == 0 {
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
// from a sender the view trusts (trustedFrom, §E.3.2). Where the key it
// holds, or the first one found, isn't, it looks on, in both relays and in
// the keyring, for an entry from one that is, and holds that key from then
// on; with none, it is ErrUntrustedKey.
func (x *E2E) SealKey(ctx context.Context, kid string) ([]byte, error) {
	x.keys.mu.Lock()
	key, from := x.keys.m[kid], x.keys.from[kid]
	x.keys.mu.Unlock()
	if key != nil && x.trustedFrom(from) {
		return key, nil
	}
	return x.findKey(ctx, kid, "", x.trustedFrom)
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
	return x.findKey(ctx, kid, via, nil)
}

// findKey fetches the epoch key of kid, from relays first, then from the
// keyring, and holds it with its sender (addKey). With accept, it takes
// only a key whose sender accept takes, looking past others, and is
// ErrUntrustedKey when it finds only those; without, the first key found.
func (x *E2E) findKey(ctx context.Context, kid, via string, accept func(from string) bool) ([]byte, error) {
	privs := x.recipients()
	if len(privs) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoKeys, kid)
	}
	ns, epoch, err := seal.ParseKid(kid)
	if err != nil {
		return nil, err
	}
	// untrusted is the sender of the first key found that accept refused.
	untrusted, refused := "", false
	take := func(key []byte, from string) bool {
		if accept != nil && !accept(from) {
			if !refused {
				untrusted, refused = from, true
			}
			return false
		}
		x.addKey(kid, key, from)
		return true
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
			// At E3 the server relays only keyring entries, each naming
			// its sender (§E.3.2); a namespace is e2e from its creation,
			// so no epoch of it was ever served as at E2 (v0.78). A key in
			// the clear, or wrapped in base mode without from, has no
			// sender: the server can have made it up, so it is skipped,
			// for reads too.
			if e.Key != nil || e.Wrapped.From == "" {
				continue
			}
			key, err := unwrapRelayed(privs, e.Wrapped, x.knownSenders())
			if err != nil {
				// Not the key for us, or from a sender this view doesn't
				// know (anyone can wrap to a thumbprint, §E.3.2): the
				// other relay or the keyring may still hold it.
				unwrapErr = fmt.Errorf("client: unwrapping %s: %w", kid, err)
				continue
			}
			if take(key, e.Wrapped.From) {
				return key, nil
			}
		}
	}
	// Then the keyring itself (a key holder may read it directly), if it
	// is the namespace's own: a branch without one reads its base's
	// through, whose entries name the base's keys, not "{branch}#{e}".
	var ringErr error
	kr, _, err := x.keyring(ctx, ns)
	switch {
	case errors.Is(err, seal.ErrFormat):
		// Not a keyring document of §E.3.2, such as one in the format
		// before v0.63: nothing opens from it (keyring).
		ringErr = err
	case err == nil:
		for _, priv := range privs {
			if key, err := kr.EpochKey(priv, kid, x.knownSenders()); err == nil {
				e, _ := kr.Entry(kid, seal.Thumbprint(priv.PublicKey()))
				if take(key, e.From) {
					return key, nil
				}
			}
		}
	case Transient(err):
		failed = err
	}
	if failed != nil {
		return nil, fmt.Errorf("client: fetching the epoch key %s: %w", kid, failed)
	}
	if refused {
		return nil, fmt.Errorf("%w: %s from %s", ErrUntrustedKey, kid, untrusted)
	}
	if unwrapErr != nil {
		return nil, unwrapErr
	}
	if ringErr != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrNoKeys, kid, ringErr)
	}
	return nil, fmt.Errorf("%w: %s", ErrNoKeys, kid)
}

// unwrapRelayed opens a K_e that /keys relays from a keyring (§E.3.2) with
// one of privs (seal.UnwrapRelayed): an entry with from in auth mode under
// the one of senders it names.
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

// errNotE2E reports a namespace whose document, or /keys, says it isn't e2e.
var errNotE2E = errors.New("client: not an e2e namespace")

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
		return nil, fmt.Errorf("%w: namespace %s (encryption.level %q)", errNotE2E, ns, lv)
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
		return nil, fmt.Errorf("%w: namespace %s (it isn't sealed)", errNotE2E, ns)
	case kerr != nil:
		return nil, fmt.Errorf("client: namespace %s: sealing needs the current epoch and pad, which neither its document (%w) nor /keys (%w) gives this grant", ns, err, kerr)
	case a.Level == "" || a.Epoch < 1:
		// A deployment before v0.51 names neither (§E.2.3).
		return nil, fmt.Errorf("client: namespace %s: sealing needs the current epoch and pad, which neither its document (%w) nor /keys gives this grant", ns, err)
	case a.Level != "e2e":
		return nil, fmt.Errorf("%w: namespace %s (encryption.level %q)", errNotE2E, ns, a.Level)
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
// acknowledged: sealing again gives another id (§E.3.1). A view's first
// sealing for ns/name reads its log to count the sealings under that K_r
// (countOnce), and one past the message bound is ErrSealBound (§E.2.1).
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
	if err := x.countOnce(ctx, ns, name); err != nil {
		return nil, err
	}
	done, err := x.reserveSeal(ns, name, kid)
	if err != nil {
		return nil, err
	}
	body, err := seal.SealPatchSetPad(kr, kid, ns, name, parent, v, cfg.Pad)
	jwe, _ := seal.SealedJWE(mustValue(body))
	done(jwe)
	if err != nil || len(blobs) == 0 {
		return body, err
	}
	return seal.WithBlobs(body, blobs)
}

// mustValue parses a sealed patch set seal just produced (nil on error).
func mustValue(body []byte) any {
	v, err := jsonv.Parse(body)
	if err != nil {
		return nil
	}
	return v
}

// --- the message bound (§E.2.1) ---------------------------------------------

// DefaultSealBound is the message bound of a key (§E.2.1): IVs are 96
// random bits, so no K_r seals 2³² values.
const DefaultSealBound int64 = 1 << 32

// DefaultSealMargin is how far below the bound a view reports rotation due
// (SealStatus): half of it, as the origin rotates its own keys
// (core.Options.SealRotateAt). It also covers what the view can't count:
// sealings of other writers that never reached the log, and those below a
// pruning horizon.
const DefaultSealMargin int64 = 1 << 31

// ErrSealBound reports a sealing the view refuses because the key would
// pass the message bound (§E.2.1: at E3 only clients seal under K_r, and
// the key holder that rotates keeps each K_r within the bound). A holder
// of a * key rotates the epoch (RotateEpoch); sealing under the new one
// goes on.
var ErrSealBound = errors.New("client: the resource's key of this epoch has reached the message bound; rotate the epoch (§E.2.1)")

// e2eSeals counts, per resource and kid, the sealings under that K_r the
// view knows of (SealStatus). Views share it, as they share keys.
type e2eSeals struct {
	mu sync.Mutex
	m  map[string]*sealCount // ns "\n" name
}

// sealCount is what a view knows of the sealings under one resource's K_r
// per epoch: the resource's own sealed ops in its log, counted up to head,
// and the sealings the view made itself that the log doesn't show (yet):
// refused writes, prune snapshots, writes not yet read back. A retry
// resends the same ciphertext, one sealing.
type sealCount struct {
	head     string // the log is counted up to head; "" none of it yet
	counted  bool   // the log was read once (countLog), or found unreadable or absent
	partial  bool   // some of the log couldn't be counted (pruned, unreadable)
	logged   map[string]int64
	local    map[string]map[[32]byte]bool
	inFlight map[string]int64
}

func (sc *sealCount) count(kid string) int64 {
	return sc.logged[kid] + int64(len(sc.local[kid])) + sc.inFlight[kid]
}

// WithSealBound returns a view that keeps each K_r within bound sealings,
// reporting rotation due once margin of them are left (SealStatus), and
// sharing the counts. 0 keeps the default (DefaultSealBound,
// DefaultSealMargin). Tests inject a small bound.
func (x *E2E) WithSealBound(bound, margin int64) *E2E {
	cp := *x
	cp.sealBound, cp.sealMargin = bound, margin
	return &cp
}

func (x *E2E) bounds() (bound, margin int64) {
	bound, margin = x.sealBound, x.sealMargin
	if bound <= 0 {
		bound = DefaultSealBound
	}
	if margin <= 0 {
		margin = DefaultSealMargin
		if margin >= bound {
			margin = bound / 2
		}
	}
	return bound, margin
}

func (x *E2E) sealCount(ns, name string) *sealCount {
	k := ns + "\n" + name
	sc := x.seals.m[k]
	if sc == nil {
		sc = &sealCount{logged: map[string]int64{}, local: map[string]map[[32]byte]bool{}, inFlight: map[string]int64{}}
		x.seals.m[k] = sc
	}
	return sc
}

// countOnce counts the log of ns/name (countLog) where the view hasn't
// yet, so that a view's first sealing under a K_r, every CLI run's among
// them, is judged against the sealings the log shows (§E.2.1), not only
// against those this view made. A grant that can't read the log (§C.5)
// counts what the view sealed; any other failure to read it fails the
// sealing.
func (x *E2E) countOnce(ctx context.Context, ns, name string) error {
	x.seals.mu.Lock()
	counted := x.sealCount(ns, name).counted
	x.seals.mu.Unlock()
	if counted {
		return nil
	}
	return x.countLog(ctx, ns, name)
}

// reserveSeal counts one sealing under the K_r of name and kid before it is
// made, refusing it with ErrSealBound where the count the view knows
// (SealStatus) would pass the bound. It makes no request: its callers count
// the log first (countOnce). done records the sealing made, its JWE (""
// if none was made).
func (x *E2E) reserveSeal(ns, name, kid string) (done func(jwe string), err error) {
	bound, _ := x.bounds()
	x.seals.mu.Lock()
	defer x.seals.mu.Unlock()
	sc := x.sealCount(ns, name)
	if sc.count(kid)+1 > bound {
		return nil, fmt.Errorf("%w: %s/%s under %s has %d sealings, the bound is %d", ErrSealBound, ns, name, kid, sc.count(kid), bound)
	}
	sc.inFlight[kid]++
	return func(jwe string) {
		x.seals.mu.Lock()
		defer x.seals.mu.Unlock()
		sc.inFlight[kid]--
		if jwe == "" {
			return
		}
		if sc.local[kid] == nil {
			sc.local[kid] = map[[32]byte]bool{}
		}
		sc.local[kid][sha256.Sum256([]byte(jwe))] = true
	}, nil
}

// SealStatus is how near one resource's K_r of the current epoch is to the
// message bound, as a view counts it (E2E.SealStatus, §E.2.1).
type SealStatus struct {
	NS, Name, Kid string
	// Sealed counts the sealings under that K_r the view knows of: the
	// resource's own sealed ops in its log (pl.ns and kid naming the
	// namespace), and the sealings the view made that the log doesn't
	// show, a refused write or a prune snapshot among them.
	Sealed int64
	// Partial is set where some of the log couldn't be counted: below a
	// pruning horizon, or for a grant that can't read the log (§C.5).
	// The margin stands for what it misses.
	Partial bool
	Bound   int64
	Margin  int64
	// RotationDue is set once Sealed is within Margin of Bound: a holder of
	// a * key rotates the epoch (RotateEpoch) before writes reach Bound,
	// which the view refuses (ErrSealBound).
	RotationDue bool
}

// SealStatus reads the log of ns/name since it last did and reports how
// near the resource's K_r of the current epoch is to the message bound
// (§E.2.1: at E3 only clients seal under K_r, and the key holder that
// rotates keeps each within the bound). Counts the view keeps are shared
// by its copies; writes refuse past the bound (ErrSealBound).
func (x *E2E) SealStatus(ctx context.Context, ns, name string) (*SealStatus, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	cfg, err := x.writeConfig(ctx, ns)
	if err != nil {
		return nil, err
	}
	kid := seal.Kid(ns, cfg.Epoch)
	if err := x.countLog(ctx, ns, name); err != nil {
		return nil, err
	}
	bound, margin := x.bounds()
	x.seals.mu.Lock()
	defer x.seals.mu.Unlock()
	sc := x.sealCount(ns, name)
	st := &SealStatus{NS: ns, Name: name, Kid: kid, Sealed: sc.count(kid), Partial: sc.partial, Bound: bound, Margin: margin}
	st.RotationDue = st.Sealed >= bound-margin
	return st, nil
}

// countLog counts the resource's own sealed ops in its log after what the
// view counted last (sealCount): an op whose pl.ns and kid name ns is one
// sealing under that kid's K_r of name, and one the view made itself
// moves from its local count to the log's. Ops a branch reads through are
// its base's, under the base's keys, and aren't counted. A log pruned
// past what was counted is read from the horizon, and one the grant can't
// read not at all; both leave the count partial. A resource purged and
// created again is counted from its new genesis on, keeping the old
// counts: its K_r is the same.
func (x *E2E) countLog(ctx context.Context, ns, name string) error {
	x.seals.mu.Lock()
	sc := x.sealCount(ns, name)
	start := sc.head
	x.seals.mu.Unlock()
	since, partial := start, false
	es, err := x.Log(ctx, ns, name, "", since)
	if IsNotFound(err) && since != "" {
		since = ""
		es, err = x.Log(ctx, ns, name, "", since)
	}
	if h := Horizon(err); IsPruned(err) && h != "" && h != since {
		partial = true
		since = h
		es, err = x.Log(ctx, ns, name, "", since)
	}
	switch {
	case err == nil:
	case IsNotFound(err) && since == "":
		// No resource yet: nothing sealed under it but what the view did.
		x.seals.mu.Lock()
		sc.counted = true
		x.seals.mu.Unlock()
		return nil
	case IsAuth(err):
		x.seals.mu.Lock()
		sc.partial, sc.counted = true, true
		x.seals.mu.Unlock()
		return nil
	default:
		return err
	}
	x.seals.mu.Lock()
	defer x.seals.mu.Unlock()
	if sc.head != start {
		// Another count moved on meanwhile: it counted these.
		return nil
	}
	sc.counted = true
	for _, e := range es {
		if e.Kind != "rev" || !e.HasPatches {
			continue
		}
		jwe, ok := seal.SealedJWE(e.Patches)
		if !ok {
			continue
		}
		kid, plNS, ok := opKid(e.Patches)
		if !ok || plNS != ns || !kidNames(kid, ns) {
			continue
		}
		sc.logged[kid]++
		delete(sc.local[kid], sha256.Sum256([]byte(jwe)))
	}
	if len(es) > 0 {
		sc.head = es[len(es)-1].ID
	} else {
		sc.head = since
	}
	sc.partial = sc.partial || partial
	return nil
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
	// ns is the namespace the document was read from, whose own ops are
	// those whose pl.ns names it (Kid, snapshotEpoch, §E.3.1).
	ns string
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

// DocE2E folds the document at revision id (§7.1 End-to-end namespaces):
// /r/{ns}/{name}/rev/{id} is a prune's stored snapshot, 200
// application/jose, opened as the document of id; or 404 not_offered,
// naming the resource's horizon and, where that is a tombstone, last, its
// parent; the reader then folds the log up to id from last, else horizon,
// whose snapshot /rev/{start} serves, else from genesis (see E2E). The
// keyring, and a namespace that isn't e2e, serve the document itself
// (Plain). Any other 200 for a resource of an e2e namespace is
// seal.ErrMismatch: the server never folds, and never serves an e2e
// document in the clear. A prune that moves the horizon past the range
// meanwhile (410 pruned) asks /rev/{id} again, once.
func (x *E2E) DocE2E(ctx context.Context, ns, name, id string) (*E2EDoc, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	if err := checkID("revision", id); err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		d, err := x.docE2E(ctx, ns, name, id)
		if attempt == 0 && IsPruned(err) {
			continue
		}
		return d, err
	}
}

func (x *E2E) docE2E(ctx context.Context, ns, name, id string) (*E2EDoc, error) {
	path := "/r/" + ns + "/" + name + "/rev/" + id
	r, err := x.c.do(ctx, "GET", path, nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status == 200 {
		e2e := false
		if name != KeyringName {
			if e2e, err = x.isE2E(ctx, ns); err != nil {
				return nil, err
			}
		}
		switch {
		case e2e && isJOSE(r):
			// A prune's stored snapshot: the document of id (§8.6,
			// §E.3.1), at the horizon or, at a tombstone horizon, at its
			// parent.
			doc, kid, err := x.openSnapshot(ctx, ns, name, id, r, x.inChainOf(ctx, ns, name, id, nil))
			if err != nil {
				return nil, err
			}
			return &E2EDoc{ID: id, Value: doc, ValidID: id, since: id, sinceKid: kid, ns: ns}, nil
		case e2e:
			return nil, fmt.Errorf("client: e2e document %s/%s@%s: the server answered 200 %s, not a sealed snapshot (§7.1): %w", ns, name, id, r.header.Get("Content-Type"), seal.ErrMismatch)
		}
		d, err := x.c.Doc(ctx, ns, name, id)
		if err != nil {
			return nil, err
		}
		return &E2EDoc{ID: id, Value: d.Value, ValidID: id, Plain: true, ns: ns}, nil
	}
	aerr := r.apiError()
	if !IsNotOffered(aerr) {
		return nil, aerr
	}
	// The reader folds (§7.1): from last, else horizon, else genesis.
	ae, _ := AsAPIError(aerr)
	since := ae.Last()
	if since == "" {
		since = ae.Horizon()
	}
	if err := checkOptID("fold start", since); err != nil {
		return nil, fmt.Errorf("client: e2e document %s/%s@%s: not_offered names %w", ns, name, id, err)
	}
	arr, err := x.foldLog(ctx, ns, name, id, since)
	if err != nil {
		return nil, err
	}
	return x.fold(ctx, ns, name, id, since, arr)
}

// isE2E reports whether ns is e2e: by its namespace document
// (EncryptionLevel, a sealed one being E2), or, for a grant that can't read
// it, such as a writer limited to some resources (§C.5), by what /keys
// names, as writeConfig does. Where neither tells, it is an error, never
// taken as not e2e: a document served in the clear by a namespace that is
// would be believed.
func (x *E2E) isE2E(ctx context.Context, ns string) (bool, error) {
	lv, err := x.c.EncryptionLevel(ctx, ns)
	if nsUnreadable(err) {
		a, kerr := x.c.FetchKeysAnswer(ctx, ns, nil, nil)
		switch {
		case IsNotOffered(kerr):
			// Neither sealed nor end-to-end (§E.2.3).
			return false, nil
		case kerr != nil:
			return false, fmt.Errorf("client: namespace %s: whether it is e2e neither its document (%w) nor /keys (%w) tells this grant", ns, err, kerr)
		case a.Level == "":
			return false, fmt.Errorf("client: namespace %s: whether it is e2e neither its document (%w) nor /keys tells this grant", ns, err)
		}
		lv, err = a.Level, nil
	}
	if err != nil {
		return false, err
	}
	return lv == "e2e", nil
}

// foldLog fetches the log a fold reads, the range after since up to id,
// following its pages (§7.1). The range never holds since's snapshot: fold
// fetches that from /rev/{since}. Every entry is plaintext JSON: one
// served as a JWE, as an e2e namespace never seals its log, is refused.
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
			for _, v := range page {
				if _, ok := v.(string); ok {
					return "", fmt.Errorf("client: e2e log of %s/%s: a sealed entry: %w", ns, name, seal.ErrMismatch)
				}
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
	if h.Zip != "" {
		// Bytes sealed before v0.65 don't open, whatever key the reader
		// holds: flagged and folded as [] (§E.2.2, §E.3.2).
		return nil, "sealed patch set: zip: sealed payloads are never compressed (§E.2.2)", "", nil
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
// name) only, kns being the pl.ns the open checks (§E.3.1). K_e itself
// seals nothing (§E.2.1): a patch set sealed under it, as before v0.65,
// doesn't open, and a fold flags it and folds it as [] (§E.3.2).
func openPatchSet(patchSet any, key []byte, kid, kns, name, parent string) (any, bool, error) {
	kr, err := resourceKey(key, kns, name)
	if err != nil {
		return nil, false, err
	}
	return seal.OpenPatchSetPadded(patchSet, kr, kid, kns, name, parent)
}

// openSnapshotJWE opens a prune snapshot of revision h of name sealed under
// the epoch key K_e of kid in namespace kns: under K_r only, bound to
// exactly {kns, name, h}, as openPatchSet.
func openSnapshotJWE(jwe string, key []byte, kid, kns, name, h string) (any, error) {
	kr, err := resourceKey(key, kns, name)
	if err != nil {
		return nil, err
	}
	return seal.OpenSnapshot(jwe, kr, kid, kns, name, h)
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
		if log, err = x.nsLogE2E(ctx, ns, head, prev.head); err == nil {
			for id, p := range prev.at {
				ph.at[id] = p
			}
			cur = prev.now
		}
	}
	if prev == nil || err != nil {
		if log, err = x.nsLogE2E(ctx, ns, head, ""); err != nil {
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

// nsLogE2E is Client.NSLog for padHistory: the namespace log of ns after
// since up to nsID, following its pages (§7.1). An e2e namespace's log is
// plaintext (the server seals nothing at E3, §E.3.1): a sealed page is
// refused.
func (x *E2E) nsLogE2E(ctx context.Context, ns, nsID, since string) ([]NSEntry, error) {
	all := []NSEntry{}
	for {
		next, err := x.c.logPage(ctx, "/ns/"+ns+"/rev/"+nsID+"/log", since, nsID, func(r *response, end string) (string, error) {
			if isJOSE(r) {
				return "", fmt.Errorf("client: namespace log of e2e namespace %s served sealed: %w", ns, seal.ErrMismatch)
			}
			es, err := parseNSLog(r.value(), r.path)
			if err != nil {
				return "", err
			}
			all = append(all, es...)
			if len(es) == 0 {
				return "", nil
			}
			return es[len(es)-1].ID, nil
		})
		if err != nil {
			return nil, err
		}
		if next == "" {
			return all, nil
		}
		since = next
	}
}

// OpenLog opens the revisions of es, log entries of ns/name as Client.Log
// returns them, and returns copies whose Patches are the plaintext patch
// sets (a restore with [] stays []; tombstones and absent patch sets are
// unchanged). A revision that can't be opened (see openSealed), which a
// fold folds as [], gets no patches (HasPatches false) and its reason in
// flags, at the same index. One that opens but isn't padded as its
// namespace padded keeps its patches and no flag, since folds still apply
// it (§E.3.2); folds flag it. The ids stay those over ciphertext. Merge
// and rebase (§F.8) read branch changes this way. What the entries follow
// places the forks of a branch's chain (chainCheck): a leading entry with
// neither kind nor patch set (a horizon, as merge plans list one), else
// the first entry's parent ("" for a genesis).
func (x *E2E) OpenLog(ctx context.Context, ns, name string, es []LogEntry) (out []LogEntry, flags []string, err error) {
	since := ""
	switch {
	case len(es) == 0:
	case es[0].Kind == "" && !es[0].HasPatches:
		since = es[0].ID
	default:
		since = es[0].Parent
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
	if since != "" {
		// The range is past since: where since is a fork, so is every
		// entry of it (as fold, which starts at since's snapshot).
		nsOK.at(since)
	}
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

// foldStart fetches the document a fold starts from at since, from
// /rev/{since}, where it is served instead of being a log entry (§7.1
// Paging, §8.6): a prune's stored snapshot, 200 application/jose, bound to
// since (openSnapshot). Anything else is an error, a mismatch where it
// isn't one. It returns the document and the kid sealing it.
func (x *E2E) foldStart(ctx context.Context, ns, name, since string, nsOK *chainCheck) (doc any, kid string, err error) {
	r, err := x.c.do(ctx, "GET", "/r/"+ns+"/"+name+"/rev/"+since, nil, nil)
	if err != nil {
		return nil, "", err
	}
	if r.status != 200 || !isJOSE(r) {
		if r.status >= 400 {
			return nil, "", r.apiError()
		}
		return nil, "", fmt.Errorf("client: e2e log of %s/%s: /rev/%s doesn't serve the snapshot the fold starts from (status %d): %w", ns, name, since, r.status, seal.ErrMismatch)
	}
	return x.openSnapshot(ctx, ns, name, since, r, nsOK)
}

// Log is Client.Log for a resource of an e2e namespace (§7.1): the log
// range of ns/name after since up to id (its head when ""), following its
// pages, its entries chained. Entries keep their sealed patch sets, which
// OpenLog opens; one served as a JWE is refused, as an e2e namespace never
// seals its log.
func (x *E2E) Log(ctx context.Context, ns, name, id, since string) ([]LogEntry, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	if err := checkOptID("since", since); err != nil {
		return nil, err
	}
	if id == "" {
		h, err := x.c.Head(ctx, ns, name)
		if err != nil {
			return nil, err
		}
		switch h.State {
		case NotFound:
			return nil, &APIError{Status: 404, Code: "not_found", Method: "GET", Path: "/r/" + ns + "/" + name}
		case Purged:
			return nil, &APIError{Status: 410, Code: "gone", Method: "GET", Path: "/r/" + ns + "/" + name}
		}
		id = h.ID
	}
	if err := checkID("revision", id); err != nil {
		return nil, err
	}
	all := []LogEntry{}
	for cur := since; ; {
		next, err := x.c.logPage(ctx, "/r/"+ns+"/"+name+"/rev/"+id+"/log", cur, id, func(r *response, end string) (string, error) {
			arr, ok := r.value().([]any)
			if !ok {
				return "", fmt.Errorf("client: %s: log is not an array", r.path)
			}
			prev := cur
			for i, v := range arr {
				if _, ok := v.(string); ok {
					return "", fmt.Errorf("client: e2e log of %s/%s: a sealed entry: %w", ns, name, seal.ErrMismatch)
				}
				e, err := parseLogEntry(v)
				if err != nil {
					return "", err
				}
				if (i > 0 || cur != "") && e.Parent != prev {
					return "", fmt.Errorf("client: log of %s/%s does not chain at %s: %w", ns, name, e.ID, seal.ErrMismatch)
				}
				prev = e.ID
				all = append(all, e)
			}
			if len(arr) == 0 {
				return "", nil
			}
			return prev, nil
		})
		if err != nil {
			return nil, err
		}
		if next == "" {
			return all, nil
		}
		cur = next
	}
}

// openSnapshot opens the sealed snapshot of h that r, the 200
// application/jose answer of /rev/{h}, serves (§7.1): a prune's, at the
// horizon or at a tombstone horizon's parent. It is sealed under ns or one
// of its bases (a branch reads its base's snapshot as it sees it, §7.6)
// and bound to exactly {kns, name, h} (§E.3.1).
func (x *E2E) openSnapshot(ctx context.Context, ns, name, h string, r *response, nsOK *chainCheck) (any, string, error) {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("client: e2e snapshot of %s/%s at %s: %s: %w", ns, name, h, fmt.Sprintf(format, args...), seal.ErrMismatch)
	}
	var jwe string
	if r.status == 200 && isJOSE(r) {
		jwe = strings.TrimSpace(string(r.body))
	}
	if jwe == "" {
		return nil, "", bad("no sealed snapshot in the answer")
	}
	hd, err := seal.ParseHeader(jwe)
	if err != nil {
		return nil, "", bad("%v", err)
	}
	if hd.Zip != "" {
		// Bytes sealed before v0.65 don't open (§E.2.2), whatever key.
		return nil, "", bad("zip: sealed payloads are never compressed (§E.2.2)")
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
// since. A fold that starts at a pruning horizon, or at a tombstone
// horizon's parent (since set, §7.1), starts from its snapshot, fetched
// from /rev/{since}.
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
	out := &E2EDoc{ID: id, log: entries, since: since, ns: ns}
	var doc any
	exists := false
	prev := ""
	bad := func(format string, args ...any) error {
		return fmt.Errorf("client: e2e log of %s/%s: %s: %w", ns, name, fmt.Sprintf(format, args...), seal.ErrMismatch)
	}
	if since != "" {
		var err error
		if doc, out.sinceKid, err = x.foldStart(ctx, ns, name, since, nsOK); err != nil {
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
		// A patch set that opened but doesn't parse or apply folds as []
		// on its parent's document (§E.3.2): for a genesis, null (§6.2
		// step 3), which then exists, the revision flagged. One that
		// doesn't open isn't known to be a patch set at all.
		ops, err := patch.Parse(plain)
		if err != nil {
			flag("patch set: " + err.Error())
			if e.Parent == "" {
				doc, exists = nil, true
			}
			continue
		}
		// A genesis applies to null (§6.2 step 3), whose document then
		// exists; a restore to the last live one.
		nd, _, err := patch.Apply(doc, true, ops, patch.Options{})
		if err != nil {
			flag("patch set doesn't apply: " + err.Error())
			if e.Parent == "" {
				doc, exists = nil, true
			}
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

// arrAt is a[i], nil out of range (an empty page included).
func arrAt(a []any, i int) any {
	if i >= 0 && i < len(a) {
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
// error when a schema couldn't be fetched. A typed document validates
// against the revision it names, each revision of whose $ref closure
// compiles under this version's rules, as the core validates it: every
// schema compiles under this version, whatever version stored it (§6.1,
// v0.74). The markers servers send (Doc.Rules) and stored, which a fold
// passes for a revision it re-validates, are still handed to the
// validator but select nothing, so a stored revision only an earlier
// version accepted, or one typed by such a schema, is flagged.
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
			x.schemas.m[ref.Path()], x.schemas.rules[ref.Path()] = r.Doc.Value, r.Doc.Rules
		} else {
			x.schemas.drafts[ref.Path()], x.schemas.draftRules[ref.Path()] = r.Doc.Value, r.Doc.Rules
		}
		x.schemas.mu.Unlock()
		return r.Doc.Value, nil
	}
	// The marker of a revision load returned, which it fetched first.
	rulesOf := func(ref schema.Ref) schema.Rules {
		x.schemas.mu.Lock()
		defer x.schemas.mu.Unlock()
		if r, ok := x.schemas.rules[ref.Path()]; ok {
			return r
		}
		if r, ok := x.schemas.draftRules[ref.Path()]; ok && drafts {
			return r
		}
		return schema.Legacy
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
	rules := schema.V073 // a schema document written now
	if stored {
		rules = schema.Legacy
	}
	err := x.schemas.v.ValidateMarked(doc, load, rules, rulesOf)
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
// document (for a tombstone horizon, the last live document, its parent's,
// to which the snapshot is bound, §E.3.1), seals it as the snapshot and
// sends the prune. If the server
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
	at, err := x.snapshotAt(ctx, ns, name, horizon)
	if err != nil {
		return nil, err
	}
	d, err := x.DocE2E(ctx, ns, name, at)
	if err != nil {
		return nil, err
	}
	cfg, err := x.writeConfig(ctx, ns)
	if err != nil {
		return nil, err
	}
	// The snapshot is sealed only under a key from a trusted sender
	// (SealKey, §E.3.2), of this namespace's epoch that the chain sets
	// (§E.3.1), and pl names this namespace and at, the horizon or, at a
	// tombstone horizon, its parent, the revision whose document it is
	// (§7.1). The server checks both (422 invalid).
	kid := snapshotKid(ns, cfg.Epoch, d)
	key, err := x.SealKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	kr, err := resourceKey(key, ns, name)
	if err != nil {
		return nil, err
	}
	if err := x.countOnce(ctx, ns, name); err != nil {
		return nil, err
	}
	done, err := x.reserveSeal(ns, name, kid)
	if err != nil {
		return nil, err
	}
	snap, err := seal.SealSnapshotPad(kr, kid, ns, name, at, d.Value, cfg.Pad)
	done(snap)
	if err != nil {
		return nil, err
	}
	// The snapshot needs no declared list: the server keeps the list of
	// the horizon's revision (§8.6, §E.3.1).
	return x.c.Prune(ctx, ns, name, PruneRequest{Horizon: horizon, Snapshot: snap})
}

// snapshotAt is the revision a prune's snapshot at horizon is the
// document of (§8.6, §E.3.1): the horizon itself, or, where it is a
// tombstone, its parent, the last live revision (§7.1). The head
// tombstone's parent is the head's last; a tombstone further down the
// chain, as a horizon the server moves a prune to may be, is found in the
// log; the current horizon, which the log no longer lists, by the
// not_offered of a revision above it. Every parent so learned is checked
// against the tombstone's id (tombstoneParent).
func (x *E2E) snapshotAt(ctx context.Context, ns, name, horizon string) (string, error) {
	h, err := x.c.Head(ctx, ns, name)
	if err != nil {
		return "", err
	}
	if h.State == Tombstoned && h.ID == horizon {
		return tombstoneParent(ns, name, horizon, h.Last)
	}
	if h.State != Tombstoned && h.ID == horizon {
		return horizon, nil
	}
	es, err := x.Log(ctx, ns, name, horizon, "")
	if hz := Horizon(err); IsPruned(err) && hz != "" {
		es, err = x.Log(ctx, ns, name, horizon, hz)
	}
	if err != nil {
		return "", err
	}
	if len(es) == 0 || es[len(es)-1].ID != horizon {
		// The range is empty: horizon is the current horizon itself, which
		// a prune doesn't move below (a retention applied again).
		return x.currentHorizonAt(ctx, ns, name, horizon, h)
	}
	e := es[len(es)-1]
	if e.Kind != "tombstone" {
		return horizon, nil
	}
	return tombstoneParent(ns, name, horizon, e.Parent)
}

// currentHorizonAt is snapshotAt for horizon, which the log no longer
// lists: the resource's current horizon, or so the caller supposes. A
// live revision above it, the head or a tombstoned head's last, answers
// /rev with 404 not_offered naming the horizon and, where that is a
// tombstone, last, its parent (§7.1), which a tombstone's own URL, a 410,
// doesn't. Only a not_offered naming this horizon is taken; any other
// answer leaves horizon, whose kind is then the server's to judge.
func (x *E2E) currentHorizonAt(ctx context.Context, ns, name, horizon string, h *Head) (string, error) {
	probe := h.ID
	if h.State == Tombstoned {
		probe = h.Last
	}
	if probe == "" || probe == horizon || checkID("revision", probe) != nil {
		return horizon, nil
	}
	r, err := x.c.do(ctx, "GET", "/r/"+ns+"/"+name+"/rev/"+probe, nil, nil)
	if err != nil {
		return "", err
	}
	if r.status == 200 {
		return horizon, nil
	}
	ae := r.apiError()
	if !IsNotOffered(ae) || ae.Horizon() != horizon || ae.Last() == "" {
		return horizon, nil
	}
	return tombstoneParent(ns, name, horizon, ae.Last())
}

// tombstoneParent is parent, which a head, log entry or not_offered names
// as tombstone horizon's parent, once horizon is checked to be the
// tombstone on it (ExpectedTombstone, §6.2): the snapshot is sealed with
// pl.id = parent (§E.3.1), so a server naming another revision is
// seal.ErrMismatch, never sealed under the horizon.
func tombstoneParent(ns, name, horizon, parent string) (string, error) {
	if want, err := ExpectedTombstone(parent); parent == "" || err != nil || want != horizon {
		return "", fmt.Errorf("client: prune of %s/%s: tombstone %s has the wrong id for its parent %q: %w", ns, name, horizon, parent, seal.ErrMismatch)
	}
	return parent, nil
}

// snapshotKid is the kid a prune's snapshot of the document d folds is
// sealed under (§E.3.1), as the server checks it: always one of ns, its
// epoch snapshotEpoch's.
func snapshotKid(ns string, current int, d *E2EDoc) string {
	return seal.Kid(ns, snapshotEpoch(ns, current, d))
}

// snapshotEpoch is snapshotKid's epoch of ns: that of the sealed op of the
// newest revision of the range d folded that isn't a tombstone and whose
// patch set isn't [], where the op is ns's own, its pl.ns naming ns, not a
// base's read through (§E.3.1), whatever namespace its kid names; current,
// the epoch in force, for a base's op. An own op whose kid names another
// namespace has no epoch of ns: it gives 0, not known, as the tree's
// born does, so the prune fails rather than seal under a guess. A
// snapshot's pl.ns is its kid's namespace (openSnapshotJWE), so below an
// earlier horizon the rule goes by its kid.
func snapshotEpoch(ns string, current int, d *E2EDoc) int {
	for i := len(d.log) - 1; i >= 0; i-- {
		e := d.log[i]
		if e.Kind == "tombstone" || !e.HasPatches {
			continue
		}
		if a, ok := e.Patches.([]any); ok && len(a) == 0 {
			continue
		}
		kid, plNS, ok := opKid(e.Patches)
		if !ok || plNS != ns {
			return current
		}
		if kns, ep, err := seal.ParseKid(kid); err == nil && kns == ns {
			return ep
		}
		return 0
	}
	if kns, ep, err := seal.ParseKid(d.sinceKid); err == nil && kns == ns && d.since != "" {
		return ep
	}
	return current
}

// --- keyring administration -------------------------------------------------

// keyring reads the keyring resource of ns as ns sees it (its base's, read
// through, in a branch without one): the keyring document (§E.3.2), and
// its head. One that isn't in that form, such as one in the format before
// v0.63, is an error wrapping seal.ErrFormat: no client reads or migrates
// it any more (v0.78, "Reading this spec"), and a key holder wraps it
// again with the v0.26.1 client before upgrading.
func (x *E2E) keyring(ctx context.Context, ns string) (kr *seal.KeyringV2, head string, err error) {
	h, d, err := x.c.Load(ctx, ns, KeyringName)
	if err != nil {
		return nil, "", err
	}
	if h.State != Live {
		return nil, "", &APIError{Status: 404, Code: "not_found", Method: "GET", Path: "/r/" + ns + "/" + KeyringName}
	}
	if kr, err = seal.ParseKeyringV2(d.Value); err != nil {
		return nil, "", fmt.Errorf("client: the keyring of %s is not in the §E.3.2 form; wrap it again with the v0.26.1 client before upgrading: %w", ns, err)
	}
	return kr, h.ID, nil
}

// Keyring reads the keyring resource of ns (§E.3.2) as ns sees it and
// returns it with its head. One not in the §E.3.2 form is an error
// wrapping seal.ErrFormat.
func (x *E2E) Keyring(ctx context.Context, ns string) (*seal.KeyringV2, string, error) {
	return x.keyring(ctx, ns)
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
	cur, head, err := x.keyring(ctx, ns)
	switch {
	case err == nil && cur.Current(ns) > 0:
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
