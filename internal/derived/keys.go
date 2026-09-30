package derived

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/seal"
)

// ErrSkip is returned by FetchDoc for a resource that is not content to a
// consumer (the keyring of an e2e namespace) or that the service cannot
// read (an e2e namespace without a keyring recipient key). Consumers treat
// it as "no document", never as ciphertext to consume.
var ErrSkip = errors.New("derived: not readable content")

// Info is what the services need of a namespace's encryption.
type Info struct {
	Level string // encryption.level ("" if none)
	Epoch int    // encryption.epoch of a sealed or e2e namespace (default 1)
	Pad   bool   // encryption.pad: sealed payloads are padded (§E.2.2)
	// HistoryEpochs is encryption.historyEpochs: how many epochs back
	// readers get keys for (0: all).
	HistoryEpochs int
}

// Protected reports whether views derived from the namespace are sealed.
func (i Info) Protected() bool { return Protected(i.Level) }

// InfoOf reads Info from a namespace document.
func InfoOf(doc map[string]any) Info {
	enc, _ := doc["encryption"].(map[string]any)
	lv, _ := enc["level"].(string)
	in := Info{Level: lv}
	in.Pad, _ = enc["pad"].(bool)
	if Protected(lv) {
		in.Epoch = 1
		if f, ok := enc["epoch"].(float64); ok && f >= 1 {
			in.Epoch = int(f)
		}
		if f, ok := enc["historyEpochs"].(float64); ok && f >= 1 {
			in.HistoryEpochs = int(f)
		}
	}
	return in
}

// Status is a followed namespace's encryption state as a service reports
// it (GET /_status).
type Status struct {
	NS      string `json:"ns"`
	Level   string `json:"level,omitempty"`
	Epoch   int    `json:"epoch,omitempty"`
	Sealed  bool   `json:"sealed"`           // derived views are served sealed
	Skipped bool   `json:"skipped"`          // the service does not consume it
	Reason  string `json:"reason,omitempty"` // why it is skipped (or partly read)
}

// Keys tracks the encryption of the namespaces a service follows, fetches
// the epoch keys that seal its views, and reads e2e documents. It is safe
// for concurrent use.
type Keys struct {
	c         *client.Client
	recipient *ecdh.PrivateKey
	e2e       *client.E2E // nil without a recipient key

	mu      sync.Mutex
	info    map[string]Info
	epoch   map[string][]byte // kid → K_e
	reasons map[string]string // ns → why it is skipped or partly read
	skipped map[string]bool
}

// NewKeys returns a tracker reading with c. recipient is the service's
// X25519 private key: it unwraps keys that POST /keys wraps to the grant's
// enc, and makes e2e namespaces readable (the keyring must name its public
// key). It may be nil.
func NewKeys(c *client.Client, recipient *ecdh.PrivateKey) *Keys {
	k := &Keys{c: c, info: map[string]Info{}, epoch: map[string][]byte{}, reasons: map[string]string{}, skipped: map[string]bool{}}
	if recipient != nil {
		k.e2e = c.E2E(recipient).WithoutValidation()
	}
	k.recipient = recipient
	return k
}

// CanReadE2E reports whether the service holds a keyring recipient key.
func (k *Keys) CanReadE2E() bool { return k.e2e != nil }

// Info returns ns's encryption, reading the namespace document at its head
// the first time (a sealed one needs the client's keys).
func (k *Keys) Info(ctx context.Context, ns string) (Info, error) {
	k.mu.Lock()
	in, ok := k.info[ns]
	k.mu.Unlock()
	if ok {
		return in, nil
	}
	lv, err := k.c.EncryptionLevel(ctx, ns)
	if err != nil {
		return Info{}, err
	}
	in = Info{Level: lv}
	if Protected(lv) {
		h, err := k.c.NSHead(ctx, ns)
		if err != nil {
			return in, err
		}
		d, err := k.c.NSDoc(ctx, ns, h.ID)
		if err != nil {
			return in, err
		}
		in = InfoOf(d.Value)
	}
	k.mu.Lock()
	k.info[ns] = in
	k.mu.Unlock()
	return in, nil
}

// Observe records the namespace document a follower delivered with a
// config change (the level or epoch may have changed).
func (k *Keys) Observe(ns string, doc map[string]any) {
	k.mu.Lock()
	k.info[ns] = InfoOf(doc)
	k.mu.Unlock()
}

// Forget drops what is known of ns and its epoch keys (after a purge-ns,
// whose keys the core destroys).
func (k *Keys) Forget(ns string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.info, ns)
	for kid := range k.epoch {
		if n, _, err := seal.ParseKid(kid); err == nil && n == ns {
			delete(k.epoch, kid)
		}
	}
}

// EpochKey returns K_e of epoch epoch of ns: from POST /ns/{ns}/keys with
// the service's grant (which must read the whole namespace: per-resource
// keys can't seal a view), unwrapped with the recipient key if wrapped; for
// an e2e namespace, relayed from or read in the keyring.
func (k *Keys) EpochKey(ctx context.Context, ns string, epoch int) ([]byte, error) {
	kid := seal.Kid(ns, epoch)
	k.mu.Lock()
	key := k.epoch[kid]
	in := k.info[ns]
	k.mu.Unlock()
	if key != nil {
		return key, nil
	}
	if in.Level == LevelE2E {
		if k.e2e == nil {
			return nil, fmt.Errorf("%w: %s (no keyring recipient key)", client.ErrNoKeys, kid)
		}
		var err error
		if key, err = k.e2e.Key(ctx, kid); err != nil {
			return nil, err
		}
	} else {
		got, err := k.c.FetchKeys(ctx, ns, []int{epoch}, nil)
		if err != nil {
			return nil, err
		}
		for _, e := range got {
			if e.Kid != kid || e.Resource != "" {
				continue
			}
			key = e.Key
			if key == nil {
				if k.recipient == nil {
					return nil, fmt.Errorf("derived: %s is wrapped to the grant's enc and no recipient key is configured", kid)
				}
				if key, err = seal.UnwrapKey(k.recipient, e.Wrapped); err != nil {
					return nil, fmt.Errorf("derived: unwrapping %s: %w", kid, err)
				}
			}
		}
		if key == nil {
			return nil, fmt.Errorf("%w: the grant gets no epoch key %s (a per-resource grant can't seal views)", client.ErrNoKeys, kid)
		}
	}
	k.mu.Lock()
	k.epoch[kid] = key
	k.mu.Unlock()
	return key, nil
}

// Current returns ns's Info and, for a sealed or e2e namespace, the Key
// that seals views derived from it now.
func (k *Keys) Current(ctx context.Context, ns string) (Info, Key, error) {
	in, err := k.Info(ctx, ns)
	if err != nil || !in.Protected() {
		return in, Key{}, err
	}
	key, err := k.EpochKey(ctx, ns, in.Epoch)
	return in, Key{NS: ns, Epoch: in.Epoch, K: key, Pad: in.Pad}, err
}

// ResourceKey is a per-resource key K_r of one epoch.
type ResourceKey struct {
	Kid      string // "{ns}#{e}"
	Resource string
	Key      []byte
}

// ResourceKeys derives K_r of ns/name (§E.2.1) for every epoch a reader
// gets keys for: from the current one back encryption.historyEpochs epochs
// (all if unset), as far as the service holds their epoch keys. It returns
// nothing for a namespace that is neither sealed nor e2e, and an error only
// if not even the current epoch's key is available.
func (k *Keys) ResourceKeys(ctx context.Context, ns, name string) ([]ResourceKey, error) {
	in, err := k.Info(ctx, ns)
	if err != nil || !in.Protected() {
		return nil, err
	}
	first := 1
	if in.HistoryEpochs > 0 {
		first = max(1, in.Epoch-in.HistoryEpochs+1)
	}
	var out []ResourceKey
	for e := in.Epoch; e >= first; e-- {
		ke, err := k.EpochKey(ctx, ns, e)
		if err != nil {
			if e == in.Epoch {
				return nil, err
			}
			continue // an epoch the service holds no key for
		}
		kr, err := seal.ResourceKey(ke, ns, name)
		if err != nil {
			return nil, err
		}
		out = append(out, ResourceKey{Kid: seal.Kid(ns, e), Resource: name, Key: kr})
	}
	return out, nil
}

// Check decides whether the service can consume ns. It returns "" if it
// can, else why not; permanent means retrying won't help without a new
// configuration (an e2e namespace and no recipient key). partial (an e2e
// namespace whose documents can't be read, which a tree service may still
// follow for heads) is reported when allowPartial and is not a skip.
func (k *Keys) Check(ctx context.Context, ns string, allowPartial bool) (reason string, permanent bool) {
	in, err := k.Info(ctx, ns)
	switch {
	case err != nil && errors.Is(err, client.ErrNoKeys):
		reason = "sealed namespace and the service has no keys for it: " + err.Error()
	case err != nil:
		// Not an encryption problem (e.g. the core is unreachable): the
		// follower's own retries report it.
		k.setReason(ns, "", false)
		return "", false
	case in.Level == LevelE2E && k.e2e == nil:
		if allowPartial {
			k.setReason(ns, "e2e namespace and no keyring recipient key: documents are not read", false)
			return "", false
		}
		reason, permanent = "e2e namespace and no keyring recipient key configured", true
	case in.Protected():
		if _, err := k.EpochKey(ctx, ns, in.Epoch); err != nil {
			reason = "cannot obtain the epoch key to seal derived views: " + err.Error()
		}
	}
	k.setReason(ns, reason, reason != "")
	return reason, permanent
}

func (k *Keys) setReason(ns, reason string, skipped bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if reason == "" {
		delete(k.reasons, ns)
	} else {
		k.reasons[ns] = reason
	}
	k.skipped[ns] = skipped
}

// Skipped returns why ns is skipped ("" if it is consumed).
func (k *Keys) Skipped(ns string) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.skipped[ns] {
		return ""
	}
	return k.reasons[ns]
}

// Status reports nss (sorted).
func (k *Keys) Status(nss []string) []Status {
	sort.Strings(nss)
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]Status, 0, len(nss))
	for _, ns := range nss {
		in := k.info[ns]
		out = append(out, Status{NS: ns, Level: in.Level, Epoch: in.Epoch, Sealed: in.Protected(), Skipped: k.skipped[ns], Reason: k.reasons[ns]})
	}
	return out
}

// FetchDoc fetches the document at revision id like follow.FetchDoc (the
// client decrypts a sealed namespace), and folds it for an e2e namespace
// with the keyring recipient key: revisions flagged by the fold (§E.3.2)
// are logged by the caller through flagged and left out. It returns
// ErrSkip for the keyring and for an e2e namespace the service can't read.
func (k *Keys) FetchDoc(ctx context.Context, ns, name, id string, flagged func(client.Flag)) (*client.Doc, error) {
	in, err := k.Info(ctx, ns)
	if err != nil {
		return nil, err
	}
	if in.Level != LevelE2E {
		return follow.FetchDoc(ctx, k.c, ns, name, id)
	}
	if name == client.KeyringName || k.e2e == nil {
		return nil, ErrSkip
	}
	d, err := k.e2e.DocE2E(ctx, ns, name, id)
	if client.IsPruned(err) {
		var h *client.Head
		h, d, err = k.e2e.LoadE2E(ctx, ns, name)
		if err == nil && h.State != client.Live {
			return nil, fmt.Errorf("%w (%s/%s is %s)", follow.ErrNotLive, ns, name, h.State)
		}
	}
	if err != nil {
		return nil, err
	}
	if d.Plain {
		// Served in the clear from an e2e namespace: not sealed content.
		return nil, ErrSkip
	}
	if flagged != nil {
		for _, f := range d.Flagged {
			flagged(f)
		}
	}
	return &client.Doc{ID: d.ID, Value: d.Value}, nil
}
