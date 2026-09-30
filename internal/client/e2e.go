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
//     ciphertext), fold from the snapshot the log starts with or from
//     genesis, and verify every intermediate document that has a $schema.
//     A revision that doesn't apply or doesn't validate is flagged with its
//     author and left out: the fold continues from the last valid document.
//   - PruneE2E folds the horizon's document and supplies it sealed as the
//     prune's snapshot (§8.6).
//   - Keyring administration (InitKeyring, AddReader, RotateEpoch) writes
//     the namespace's plaintext "keyring" resource (seal.Keyring), and
//     RotateEpoch bumps encryption.epoch in the same batch.
//
// Epoch keys come from keys added with AddKey, else (with a recipient
// private key) from POST /ns/{ns}/keys, which relays the keyring entries
// wrapped for the grant's enc, else from the keyring resource itself.

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"net/url"
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
	keys       *e2eKeys
	schemas    *e2eSchemas
	noValidate bool
}

type e2eKeys struct {
	mu sync.Mutex
	m  map[string][]byte // kid -> K_e
}

type e2eSchemas struct {
	v  *schema.Validator
	mu sync.Mutex
	m  map[string]any // schema revision path -> document
}

// E2E returns an e2e view of c. recipient is the private key whose public
// key the keyring (and the grant's enc) names; it may be nil when keys are
// added with AddKey.
func (c *Client) E2E(recipient *ecdh.PrivateKey) *E2E {
	return &E2E{c: c, recipient: recipient, keys: &e2eKeys{m: map[string][]byte{}},
		schemas: &e2eSchemas{v: schema.NewValidator(), m: map[string]any{}}}
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
	x.keys.mu.Lock()
	k := x.keys.m[kid]
	x.keys.mu.Unlock()
	if k != nil {
		return k, nil
	}
	if x.recipient == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoKeys, kid)
	}
	ns, epoch, err := seal.ParseKid(kid)
	if err != nil {
		return nil, err
	}
	// The relay first (§E.2.3): it needs a read grant with enc.
	if got, err := x.c.FetchKeys(ctx, ns, []int{epoch}, nil); err == nil {
		for _, e := range got {
			if e.Kid != kid || e.Resource != "" {
				continue
			}
			key := e.Key
			if key == nil {
				if key, err = seal.UnwrapKey(x.recipient, e.Wrapped); err != nil {
					return nil, fmt.Errorf("client: unwrapping %s: %w", kid, err)
				}
			}
			x.AddKey(kid, key)
			return key, nil
		}
	}
	// Then the keyring itself (a key holder may read it directly).
	kr, _, err := x.Keyring(ctx, ns)
	if err == nil {
		if key, err := kr.EpochKey(x.recipient, epoch); err == nil {
			x.AddKey(kid, key)
			return key, nil
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
	if b, ok := d.Value["base"].(map[string]any); ok {
		out.Base, _ = b["ns"].(string)
	}
	return out, nil
}

// --- writes ---------------------------------------------------------------

// SealPatches seals patches for a write to ns/name on parent ("" for
// genesis) under the namespace's current epoch, and returns the patch set
// to send: [{"op":"sealed","value":"<JWE>"}]. Keep the bytes until the
// write is acknowledged: sealing again gives another id (§E.3.1).
func (x *E2E) SealPatches(ctx context.Context, ns, name, parent string, patches any) ([]byte, error) {
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
	return seal.SealPatchSet(key, kid, ns, name, parent, v)
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

// validateWrite checks the document patches produce on base (a revision
// id, "" for genesis) against its $schema before writing.
func (x *E2E) validateWrite(ctx context.Context, ns, name, base string, patches any) error {
	if x.noValidate {
		return nil
	}
	v, err := ToValue(patches)
	if err != nil {
		return err
	}
	var doc any
	exists := false
	if base != "" {
		d, err := x.DocE2E(ctx, ns, name, base)
		if err != nil {
			return err
		}
		doc, exists = d.Value, true
	}
	ops, err := patch.Parse(v)
	if err != nil {
		return fmt.Errorf("client: e2e write %s/%s: %w", ns, name, err)
	}
	nd, _, err := patch.Apply(doc, exists, ops, patch.Options{})
	if err != nil {
		return fmt.Errorf("client: e2e write %s/%s: %w", ns, name, err)
	}
	if msg, err := x.validate(ctx, nd); err != nil {
		return err
	} else if msg != "" {
		return fmt.Errorf("client: e2e write %s/%s: the document doesn't validate against its $schema: %s", ns, name, msg)
	}
	return nil
}

// CreateSealed creates ns/name with a sealed genesis patch set.
func (x *E2E) CreateSealed(ctx context.Context, ns, name string, patches any, opts ...WriteOption) (*WriteResult, error) {
	if err := x.validateWrite(ctx, ns, name, "", patches); err != nil {
		return nil, err
	}
	body, err := x.SealPatches(ctx, ns, name, "", patches)
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
	if err := x.validateWrite(ctx, ns, name, parent, patches); err != nil {
		return nil, err
	}
	body, err := x.SealPatches(ctx, ns, name, parent, patches)
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
	if !x.noValidate {
		h, err := x.c.Head(ctx, ns, name)
		if err != nil {
			return nil, err
		}
		if h.State != Tombstoned || h.ID != tombstone {
			return nil, fmt.Errorf("client: restore %s/%s: %s is not the head tombstone", ns, name, tombstone)
		}
		if err := x.validateWrite(ctx, ns, name, h.Last, patches); err != nil {
			return nil, err
		}
	}
	body, err := x.SealPatches(ctx, ns, name, tombstone, patches)
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

func (x *E2E) foldLog(ctx context.Context, ns, name, id, since string) ([]any, error) {
	var q url.Values
	if since != "" {
		if err := checkID("since", since); err != nil {
			return nil, err
		}
		q = url.Values{"since": {since}}
	}
	r, err := x.c.do(ctx, "GET", "/r/"+ns+"/"+name+"/rev/"+id+"/log", q, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	arr, ok := r.value().([]any)
	if !ok {
		return nil, fmt.Errorf("client: %s: log is not an array", r.path)
	}
	return arr, nil
}

// chain lists ns and its bases (a branch reads its base's ciphertext, whose
// patch sets and snapshots are bound to the base, §F.8).
func (x *E2E) chain(ctx context.Context, ns string) (map[string]bool, error) {
	out := map[string]bool{}
	for cur := ns; cur != "" && !out[cur]; {
		out[cur] = true
		cfg, err := x.config(ctx, cur)
		if err != nil {
			return nil, err
		}
		cur = cfg.Base
	}
	return out, nil
}

// fold verifies and folds a log answer ending at id and starting after
// since (with its snapshot first when since is set).
func (x *E2E) fold(ctx context.Context, ns, name, id, since string, arr []any) (*E2EDoc, error) {
	var allowed map[string]bool
	nsOK := func(kns string) (bool, error) {
		if kns == ns {
			return true, nil
		}
		if allowed == nil {
			var err error
			if allowed, err = x.chain(ctx, ns); err != nil {
				return false, err
			}
		}
		return allowed[kns], nil
	}
	out := &E2EDoc{ID: id}
	var doc any
	exists := false
	prev := ""
	bad := func(format string, args ...any) error {
		return fmt.Errorf("client: e2e log of %s/%s: %s: %w", ns, name, fmt.Sprintf(format, args...), seal.ErrMismatch)
	}
	i := 0
	if since != "" {
		m, _ := arrAt(arr, 0).(map[string]any)
		jwe := str(m, "snapshot")
		if str(m, "kind") != "snapshot" || str(m, "id") != since || jwe == "" {
			return nil, bad("the range after %s doesn't start with its snapshot", since)
		}
		h, err := seal.ParseHeader(jwe)
		if err != nil {
			return nil, bad("snapshot: %v", err)
		}
		kns, _, err := seal.ParseKid(h.Kid)
		if err != nil {
			return nil, bad("snapshot kid: %v", err)
		}
		if ok, err := nsOK(kns); err != nil {
			return nil, err
		} else if !ok {
			return nil, bad("snapshot sealed under %s", h.Kid)
		}
		key, err := x.Key(ctx, h.Kid)
		if err != nil {
			return nil, err
		}
		if doc, err = seal.OpenSnapshot(jwe, key, h.Kid, kns, name, since); err != nil {
			return nil, fmt.Errorf("client: e2e snapshot of %s/%s at %s: %w", ns, name, since, err)
		}
		exists, prev, out.ValidID = true, since, since
		i = 1
	}
	for ; i < len(arr); i++ {
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
		jwe, ok := seal.SealedJWE(e.Patches)
		if !ok {
			flag("not a sealed patch set")
			continue
		}
		h, err := seal.ParseHeader(jwe)
		if err != nil {
			flag("sealed patch set: " + err.Error())
			continue
		}
		kns, _, err := seal.ParseKid(h.Kid)
		if err != nil {
			flag("sealed patch set: " + err.Error())
			continue
		}
		if ok, err := nsOK(kns); err != nil {
			return nil, err
		} else if !ok {
			flag("sealed under another namespace's key " + h.Kid)
			continue
		}
		key, err := x.Key(ctx, h.Kid)
		if err != nil {
			return nil, err
		}
		plain, err := seal.OpenPatchSet(e.Patches, key, h.Kid, kns, name, e.Parent)
		if err != nil {
			flag("sealed patch set: " + err.Error())
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
		msg, err := x.validate(ctx, nd)
		if err != nil {
			return nil, err
		}
		if msg != "" {
			flag("the document doesn't validate against its $schema: " + msg)
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
func (x *E2E) validate(ctx context.Context, doc any) (string, error) {
	m, ok := doc.(map[string]any)
	if !ok {
		return "", nil
	}
	if _, has := m["$schema"]; !has {
		return "", nil
	}
	load := func(ref schema.Ref) (any, error) {
		x.schemas.mu.Lock()
		d, ok := x.schemas.m[ref.Path()]
		x.schemas.mu.Unlock()
		if ok {
			return d, nil
		}
		sd, err := x.c.Doc(ctx, ref.NS, ref.Name, ref.Rev)
		if err != nil {
			if IsNotFound(err) || IsGone(err) || IsAuth(err) {
				return nil, schema.ErrUnavailable
			}
			return nil, &errSchemaLoad{err}
		}
		x.schemas.mu.Lock()
		x.schemas.m[ref.Path()] = sd.Value
		x.schemas.mu.Unlock()
		return sd.Value, nil
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
	snap, err := seal.SealSnapshot(key, kid, ns, name, horizon, d.Value)
	if err != nil {
		return nil, err
	}
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
