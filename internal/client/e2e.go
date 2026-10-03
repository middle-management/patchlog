package client

// End-to-end namespaces (Addendum E, level E3).
//
// The server of an e2e namespace never sees plaintext: clients seal patch
// sets before writing and fold the log themselves when reading. E2E is the
// key-holding view of a Client that does both:
//
//   - Writes (CreateSealed, AppendSealed, RestoreSealed) seal the patch set
//     with seal.SealPatchSet under the namespace's current epoch key, bound
//     to {ns, name, parent}, and resend exactly the same bytes on a retry,
//     so the id stays the same (§E.3.1). Unless WithoutValidation, the
//     resulting document is validated against its $schema first (§E.3.2:
//     validation moves to clients).
//   - Reads (DocE2E, LoadE2E) follow the X-E2E: fold redirect of
//     /r/{ns}/{name}/rev/{id} to the log, open every sealed patch set
//     (checking kid, pl {ns, name, parent}, the id chain and each id over the
//     ciphertext), fold from genesis or, when the redirect's since is a
//     pruning horizon, from its sealed snapshot, which /rev/{since} serves
//     (never the log, §7.1 Paging, §8.6), and verify every intermediate
//     document that has a $schema. /rev/{id} of a horizon answers its
//     snapshot directly (X-E2E: snapshot).
//     A revision that doesn't apply or doesn't validate is flagged with its
//     author and left out: the fold continues from the last valid document.
//   - PruneE2E folds the horizon's document and supplies it sealed as the
//     prune's snapshot (§8.6), with its declared blob list.
//   - Blobs (§E.3.1, sealedblobs.go). Writes declare the blobs of the
//     resulting document in the sealed op (BlobIDs), so a write folds the
//     document even WithoutValidation; folds flag a revision whose list
//     differs from its decrypted document.
//   - Keyring administration (InitKeyring, AddReader, RotateEpoch) writes
//     the namespace's plaintext "keyring" resource (seal.Keyring), and
//     RotateEpoch bumps encryption.epoch in the same batch.
//
// Epoch keys come from keys added with AddKey, else (with a recipient
// private key) from POST /ns/{ns}/keys, which relays the keyring entries
// wrapped for the grant's enc, else from the namespace's own keyring
// resource (not one read through from a base: its keys are the base's).
//
// Padding (§E.2.2, §E.3.1). In a namespace with "encryption": { "pad":
// true } writes pad the plaintext of every sealed patch set (and prune
// snapshot) to its size bucket, uncompressed (seal.SealPatchSetPad). A
// fold flags a patch set that isn't padded when the namespace that sealed
// it padded at the time, like a failed validation. Turning pad on doesn't
// flag what was sealed before: the namespace log tells which configuration
// each revision was written under.
//
// Merge and rebase (§F.8) read a branch's changes as plaintext with
// OpenLog and write them under the target's keys with SealPatches.

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

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
	c          *Client
	recipient  *ecdh.PrivateKey
	extra      []*ecdh.PrivateKey // more recipients to unwrap with (WithRecipient)
	keys       *e2eKeys
	schemas    *e2eSchemas
	pads       *e2ePads
	noValidate bool
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
}

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
	return &E2E{c: c, recipient: recipient, keys: &e2eKeys{m: map[string][]byte{}},
		schemas: &e2eSchemas{v: schema.NewValidator(), m: map[string]any{}, drafts: map[string]any{}, branch: map[string]bool{}}, pads: &e2ePads{m: map[string]*padHistory{}}}
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

// AddKey caches the epoch key of kid "{ns}#{e}".
func (x *E2E) AddKey(kid string, key []byte) {
	x.keys.mu.Lock()
	x.keys.m[kid] = append([]byte(nil), key...)
	x.keys.mu.Unlock()
}

// Key returns the epoch key of kid, fetching and unwrapping it if needed.
func (x *E2E) Key(ctx context.Context, kid string) ([]byte, error) {
	return x.keyVia(ctx, kid, "")
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
	// The relays first (§E.2.3): they need a read grant with enc.
	relays := []string{ns}
	if via != "" && via != ns {
		relays = []string{via, ns}
	}
	for _, relay := range relays {
		got, err := x.c.FetchKeys(ctx, relay, []int{epoch}, nil)
		if err != nil {
			continue
		}
		for _, e := range got {
			if e.Kid != kid || e.Resource != "" {
				continue
			}
			key := e.Key
			if key == nil {
				var uerr error
				for _, priv := range privs {
					if key, uerr = seal.UnwrapKey(priv, e.Wrapped); uerr == nil {
						break
					}
				}
				if uerr != nil {
					return nil, fmt.Errorf("client: unwrapping %s: %w", kid, uerr)
				}
			}
			x.AddKey(kid, key)
			return key, nil
		}
	}
	// Then the keyring itself (a key holder may read it directly), if it
	// is the namespace's own: a branch without one reads its base's
	// through, and those are the base's keys, not "{branch}#{e}".
	kr, _, err := x.Keyring(ctx, ns)
	if err == nil && kr.NS == ns {
		for _, priv := range privs {
			if key, err := kr.EpochKey(priv, epoch); err == nil {
				x.AddKey(kid, key)
				return key, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrNoKeys, kid)
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
	Pad   bool // encryption.pad (§E.2.2)
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

// --- writes ---------------------------------------------------------------

// SealPatches seals patches for a write to ns/name on parent ("" for
// genesis) under the namespace's current epoch, padded if the namespace
// pads, and returns the patch set to send:
// [{"op":"sealed","value":"<JWE>"}]. Keep the bytes until the write is
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
	cfg, err := x.config(ctx, ns)
	if err != nil {
		return nil, err
	}
	kid := seal.Kid(ns, cfg.Epoch)
	key, err := x.Key(ctx, kid)
	if err != nil {
		return nil, err
	}
	body, err := seal.SealPatchSetPad(key, kid, ns, name, parent, v, cfg.Pad)
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
	var doc any
	exists := false
	if base != "" {
		d, err := x.DocE2E(ctx, ns, name, base)
		if err != nil {
			return fail(err)
		}
		doc, exists = d.Value, true
	}
	ops, err := patch.Parse(v)
	if err != nil {
		return fail(fmt.Errorf("client: e2e write %s/%s: %w", ns, name, err))
	}
	nd, _, err := patch.Apply(doc, exists, ops, patch.Options{})
	if err != nil {
		return fail(fmt.Errorf("client: e2e write %s/%s: %w", ns, name, err))
	}
	if !x.noValidate {
		if msg, err := x.validate(ctx, ns, nd); err != nil {
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

// Flag is a revision that was left out of a fold: it didn't open, apply or
// validate. Its author, recorded by the server, is accountable (§E.3.2).
type Flag struct {
	ID      string
	Author  string
	Message string
}

// E2EDoc is a folded e2e document.
type E2EDoc struct {
	ID string // the revision asked for
	// Value is the document as of ID, without the flagged revisions: the
	// document of the last valid revision (ValidID).
	Value   any
	ValidID string
	Flagged []Flag
	// Plain is set when the server served the document itself (the
	// keyring, or a namespace that isn't e2e).
	Plain bool
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
		doc, err := x.openSnapshot(ctx, ns, name, id, r, x.inChain(ctx, ns))
		if err != nil {
			return nil, err
		}
		return &E2EDoc{ID: id, Value: doc, ValidID: id}, nil
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
// writes.
type chainCheck struct {
	x      *E2E
	ctx    context.Context
	ns     string
	depth  map[string]int
	remote map[string]bool
	last   int
}

func (x *E2E) inChain(ctx context.Context, ns string) *chainCheck {
	return &chainCheck{x: x, ctx: ctx, ns: ns, last: -1}
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
	}
	if c.last >= 0 && d > c.last {
		return false, nil
	}
	c.last = d
	return true, nil
}

// isRemote reports a remote base, whose configuration isn't readable here.
func (c *chainCheck) isRemote(kns string) bool { return c.remote[kns] }

// openSealed opens the sealed patch set of revision e of name. A non-empty
// flag says why the revision must be left out instead: it isn't a sealed
// patch set, is sealed under a namespace nsOK refuses, doesn't open or
// verify, or isn't padded although the namespace that sealed it padded at
// the time (§E.3.1). err is for failures that aren't the revision's fault
// (keys, transport).
func (x *E2E) openSealed(ctx context.Context, name string, e LogEntry, nsOK *chainCheck) (plain any, flag string, err error) {
	jwe, ok := seal.SealedJWE(e.Patches)
	if !ok {
		return nil, "not a sealed patch set", nil
	}
	h, err := seal.ParseHeader(jwe)
	if err != nil {
		return nil, "sealed patch set: " + err.Error(), nil
	}
	kns, _, err := seal.ParseKid(h.Kid)
	if err != nil {
		return nil, "sealed patch set: " + err.Error(), nil
	}
	if ok, err := nsOK.ok(kns); err != nil {
		return nil, "", err
	} else if !ok {
		return nil, "sealed under another namespace's key " + h.Kid, nil
	}
	key, err := x.keyVia(ctx, h.Kid, nsOK.ns)
	if err != nil {
		return nil, "", err
	}
	plain, padded, err := seal.OpenPatchSetPadded(e.Patches, key, h.Kid, kns, name, e.Parent)
	if err != nil {
		return nil, "sealed patch set: " + err.Error(), nil
	}
	// A remote base's padding history isn't readable here (§G.5.2).
	if !padded && !nsOK.isRemote(kns) {
		if must, err := x.paddedAt(ctx, kns, e.ID); err != nil {
			return nil, "", err
		} else if must {
			return nil, "the sealed patch set isn't padded to its size bucket, but " + kns + " pads (§E.2.2)", nil
		}
	}
	return plain, "", nil
}

// paddedAt reports whether ns padded when revision id was written: the
// pad of the configuration in force at its entry in ns's log. A namespace
// that doesn't pad now is taken never to require it (nothing is flagged
// after pad is turned off), and a revision the log doesn't list (yet) is
// judged by the current configuration.
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
	if err != nil {
		return false, err
	}
	if ph == nil || ph.head != h.ID {
		if ph, err = x.padHistory(ctx, ns, h.ID); err != nil {
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
// names, whether the namespace padded when it was written. Items of a
// batch that also changes the configuration were sealed under the one
// before it.
func (x *E2E) padHistory(ctx context.Context, ns, head string) (*padHistory, error) {
	d, err := x.c.NSDoc(ctx, ns, head)
	if err != nil {
		return nil, err
	}
	ph := &padHistory{head: head, now: padOf(d.Value), at: map[string]bool{}}
	if !ph.now {
		return ph, nil
	}
	log, err := x.c.NSLog(ctx, ns, head, "")
	if err != nil {
		return nil, err
	}
	cur := false
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
		visit(e)
		if e.Kind == "config" || (e.Kind == "batch" && len(e.Entries) > 0 && e.Entries[0].Kind == "config") {
			d, err := x.c.NSDoc(ctx, ns, e.ID)
			if err != nil {
				return nil, err
			}
			cur = padOf(d.Value)
		}
	}
	return ph, nil
}

// OpenLog opens the revisions of es, log entries of ns/name as Client.Log
// returns them, and returns copies whose Patches are the plaintext patch
// sets (a restore with [] stays []; tombstones and absent patch sets are
// unchanged). A revision that would be flagged in a fold (see openSealed)
// gets no patches (HasPatches false) and its reason in flags, at the same
// index. The ids stay those over ciphertext. Merge and rebase (§F.8) read
// branch changes this way.
func (x *E2E) OpenLog(ctx context.Context, ns, name string, es []LogEntry) (out []LogEntry, flags []string, err error) {
	nsOK := x.inChain(ctx, ns)
	out = make([]LogEntry, len(es))
	flags = make([]string, len(es))
	for i, e := range es {
		out[i] = e
		if e.Kind == "tombstone" || !e.HasPatches {
			continue
		}
		if a, ok := e.Patches.([]any); ok && len(a) == 0 {
			continue
		}
		plain, msg, err := x.openSealed(ctx, name, e, nsOK)
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
	return x.validate(ctx, "", doc)
}

// ValidateIn is Validate for a document written to namespace target,
// resolving $schema as the target's gate would (§6.1, §F.8.1): in a branch,
// a path its namespace can't resolve is looked up among drafts in that
// namespace's branches; elsewhere only in the schema namespaces themselves.
func (x *E2E) ValidateIn(ctx context.Context, target string, doc any) (string, error) {
	if x.noValidate {
		return "", nil
	}
	return x.validate(ctx, target, doc)
}

// snapshot fetches the sealed snapshot of the pruning horizon h of ns/name
// from /rev/{h}, where it is served instead of being a log entry (§7.1
// Paging, §8.6), and opens it.
func (x *E2E) snapshot(ctx context.Context, ns, name, h string, nsOK *chainCheck) (any, error) {
	r, err := x.c.do(ctx, "GET", "/r/"+ns+"/"+name+"/rev/"+h, nil, nil)
	if err != nil {
		return nil, err
	}
	if (r.status != 200 && r.status != 410) || r.header.Get("X-E2E") != "snapshot" {
		if r.status >= 400 {
			return nil, r.apiError()
		}
		return nil, fmt.Errorf("client: e2e log of %s/%s: /rev/%s doesn't serve the snapshot the fold starts from (status %d): %w", ns, name, h, r.status, seal.ErrMismatch)
	}
	return x.openSnapshot(ctx, ns, name, h, r, nsOK)
}

// openSnapshot opens the sealed snapshot of h that r, the answer of
// /rev/{h} with X-E2E: snapshot, serves: its body (200 application/jose),
// or for a tombstone horizon the "snapshot" member of its 410 body (the
// last live document). The snapshot is sealed under ns or one of its bases
// (a branch reads its base's ciphertext, §F.8) and bound to {name, h}.
func (x *E2E) openSnapshot(ctx context.Context, ns, name, h string, r *response, nsOK *chainCheck) (any, error) {
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
		return nil, bad("no sealed snapshot in the answer")
	}
	hd, err := seal.ParseHeader(jwe)
	if err != nil {
		return nil, bad("%v", err)
	}
	kns, _, err := seal.ParseKid(hd.Kid)
	if err != nil {
		return nil, bad("kid: %v", err)
	}
	if ok, err := nsOK.ok(kns); err != nil {
		return nil, err
	} else if !ok {
		return nil, bad("sealed under %s", hd.Kid)
	}
	key, err := x.keyVia(ctx, hd.Kid, ns)
	if err != nil {
		return nil, err
	}
	doc, err := seal.OpenSnapshot(jwe, key, hd.Kid, kns, name, h)
	if err != nil {
		return nil, fmt.Errorf("client: e2e snapshot of %s/%s at %s: %w", ns, name, h, err)
	}
	return doc, nil
}

// fold verifies and folds a log answer ending at id and starting after
// since. A fold that starts at a pruning horizon (since set) starts from
// its snapshot, fetched from /rev/{since}.
func (x *E2E) fold(ctx context.Context, ns, name, id, since string, arr []any) (*E2EDoc, error) {
	nsOK := x.inChain(ctx, ns)
	out := &E2EDoc{ID: id}
	var doc any
	exists := false
	prev := ""
	bad := func(format string, args ...any) error {
		return fmt.Errorf("client: e2e log of %s/%s: %s: %w", ns, name, fmt.Sprintf(format, args...), seal.ErrMismatch)
	}
	if since != "" {
		var err error
		if doc, err = x.snapshot(ctx, ns, name, since, nsOK); err != nil {
			return nil, err
		}
		exists, prev, out.ValidID = true, since, since
	}
	for i := 0; i < len(arr); i++ {
		e, err := parseLogEntry(arr[i])
		if err != nil {
			return nil, err
		}
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
			out.ValidID = e.ID
			continue
		}
		flag := func(msg string) { out.Flagged = append(out.Flagged, Flag{ID: e.ID, Author: e.Author, Message: msg}) }
		plain, msg, err := x.openSealed(ctx, name, e, nsOK)
		if err != nil {
			return nil, err
		}
		if msg != "" {
			flag(msg)
			continue
		}
		ops, err := patch.Parse(plain)
		if err != nil {
			flag("patch set: " + err.Error())
			continue
		}
		nd, _, err := patch.Apply(doc, exists, ops, patch.Options{})
		if err != nil {
			flag("patch set doesn't apply: " + err.Error())
			continue
		}
		msg, err = x.validate(ctx, ns, nd)
		if err != nil {
			return nil, err
		}
		if msg != "" {
			flag("the document doesn't validate against its $schema: " + msg)
			continue
		}
		if _, declared, _ := seal.SealedOp(e.Patches); !sameBlobs(declared, BlobIDs(nd)) {
			flag("the declared blob list doesn't match the blobs the document references (§E.3.1)")
			continue
		}
		doc, exists, out.ValidID = nd, true, e.ID
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
// error when a schema couldn't be fetched.
func (x *E2E) validate(ctx context.Context, target string, doc any) (string, error) {
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
	err := x.schemas.v.Validate(doc, load)
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
	cfg, err := x.config(ctx, ns)
	if err != nil {
		return nil, err
	}
	kid := seal.Kid(ns, cfg.Epoch)
	key, err := x.Key(ctx, kid)
	if err != nil {
		return nil, err
	}
	snap, err := seal.SealSnapshotPad(key, kid, ns, name, horizon, d.Value, cfg.Pad)
	if err != nil {
		return nil, err
	}
	// The snapshot needs no declared list: the server keeps the list of
	// the horizon's revision (§8.6, §E.3.1).
	return x.c.Prune(ctx, ns, name, PruneRequest{Horizon: horizon, Snapshot: snap})
}

// --- keyring administration -------------------------------------------------

// Keyring reads the keyring resource of ns and returns it with its head.
func (x *E2E) Keyring(ctx context.Context, ns string) (*seal.Keyring, string, error) {
	h, d, err := x.c.Load(ctx, ns, KeyringName)
	if err != nil {
		return nil, "", err
	}
	if h.State != Live {
		return nil, "", &APIError{Status: 404, Code: "not_found", Method: "GET", Path: "/r/" + ns + "/" + KeyringName}
	}
	kr, err := seal.ParseKeyring(d.Value)
	if err != nil {
		return nil, "", err
	}
	return kr, h.ID, nil
}

// withSelf adds the view's own recipient to readers, once.
func (x *E2E) withSelf(readers []*ecdh.PublicKey) []*ecdh.PublicKey {
	seen := map[string]bool{}
	var out []*ecdh.PublicKey
	if x.recipient != nil {
		readers = append([]*ecdh.PublicKey{x.recipient.PublicKey()}, readers...)
	}
	for _, r := range readers {
		if rid := seal.RecipientID(r); !seen[rid] {
			seen[rid] = true
			out = append(out, r)
		}
	}
	return out
}

func replaceRoot(v any) []any {
	return []any{map[string]any{"op": "replace", "path": "", "value": v}}
}

// InitKeyring creates the keyring of ns: a fresh key for the current epoch,
// wrapped for readers and for the view's own recipient. In a branch that
// reads its base's keyring through, it replaces it with the branch's own
// (a first write on the foreign parent, §7.6).
func (x *E2E) InitKeyring(ctx context.Context, ns string, readers ...*ecdh.PublicKey) (*WriteResult, error) {
	cfg, err := x.config(ctx, ns)
	if err != nil {
		return nil, err
	}
	key := seal.NewKey()
	kr, err := seal.BuildKeyring(ns, cfg.Epoch, key, x.withSelf(readers))
	if err != nil {
		return nil, err
	}
	var w *WriteResult
	cur, head, err := x.Keyring(ctx, ns)
	switch {
	case err == nil && cur.NS == ns:
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
// reader) and, with history, every older epoch the view can unwrap.
func (x *E2E) AddReader(ctx context.Context, ns string, reader *ecdh.PublicKey, history bool) (*WriteResult, error) {
	kr, head, err := x.Keyring(ctx, ns)
	if err != nil {
		return nil, err
	}
	for e := range kr.Epochs {
		if e != kr.Current && !history {
			continue
		}
		key, err := x.Key(ctx, seal.Kid(ns, e))
		if err != nil {
			if e == kr.Current {
				return nil, err
			}
			continue
		}
		if err := kr.Add(reader, e, key); err != nil {
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
	kr, head, err := x.Keyring(ctx, ns)
	if err != nil {
		return 0, err
	}
	cfg, err := x.config(ctx, ns)
	if err != nil {
		return 0, err
	}
	if kr.Current != cfg.Epoch {
		return 0, fmt.Errorf("client: the keyring of %s is at epoch %d but encryption.epoch is %d", ns, kr.Current, cfg.Epoch)
	}
	key := seal.NewKey()
	e, err := kr.Rotate(key, x.withSelf(readers))
	if err != nil {
		return 0, err
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
