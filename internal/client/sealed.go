package client

// Sealed namespaces (Addendum E, level E2).
//
// A sealed namespace serves content as JWEs (Content-Type application/jose):
// documents, namespace documents and namespace log ranges as one JWE each,
// resource logs as a JSON array of per-entry JWEs, and event payloads as a
// JWE on the SSE data line. With WithKeys, Doc, Log, NSDoc, NSLog, LongPoll,
// ResourceLongPoll, NSEvents and ResourceEvents decrypt transparently and
// return exactly what an unsealed namespace would serve. Every JWE is
// checked against what was asked for (its kid names the namespace, and its
// pl the resource, revision, kind or range; seal.OpenExpect), and resource
// log entries must chain. Without keys, sealed content is ErrNoKeys.
//
// Keys come from POST /ns/{ns}/keys with the client's grant, and are cached
// by kid (and per resource for per-resource grants). With a recipient
// private key (NewKeys), keys wrapped to the grant's enc are unwrapped.

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// ErrNoKeys reports sealed content (Addendum E.2) the client has no key for:
// it was built without WithKeys, or its grant gets no key for that epoch or
// resource.
var ErrNoKeys = errors.New("client: the content is sealed and no key is available")

// Keys caches the keys of sealed namespaces and fetches missing ones with
// POST /ns/{ns}/keys. It is safe for concurrent use and may be shared by
// clients with the same grant.
type Keys struct {
	mu        sync.Mutex
	recipient *ecdh.PrivateKey
	epoch     map[string][]byte // kid -> K_e
	res       map[string][]byte // kid "\n" resource -> K_r
	noFetch   bool
	// bases caches, per server and e2e namespace, the namespaces of its
	// base chain (readThrough); nil for a namespace that isn't e2e.
	bases map[string]map[string]bool
}

// NewKeys returns an empty key cache. recipient, if not nil, unwraps keys
// the server wraps to the grant's enc (§E.2.3).
func NewKeys(recipient *ecdh.PrivateKey) *Keys {
	return &Keys{recipient: recipient, epoch: map[string][]byte{}, res: map[string][]byte{}}
}

// StaticKeys returns a key cache that never fetches: only keys added with
// Add and AddResource are used.
func StaticKeys() *Keys {
	k := NewKeys(nil)
	k.noFetch = true
	return k
}

// Add caches an epoch key K_e under its kid "{ns}#{e}".
func (k *Keys) Add(kid string, key []byte) {
	k.mu.Lock()
	k.epoch[kid] = append([]byte(nil), key...)
	k.mu.Unlock()
}

// AddResource caches a per-resource key K_r.
func (k *Keys) AddResource(kid, resource string, key []byte) {
	k.mu.Lock()
	k.res[kid+"\n"+resource] = append([]byte(nil), key...)
	k.mu.Unlock()
}

func (k *Keys) cached(kid, resource string) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	if resource != "" {
		if r, ok := k.res[kid+"\n"+resource]; ok {
			return r
		}
	}
	ke, ok := k.epoch[kid]
	if !ok {
		return nil
	}
	if resource == "" {
		return ke
	}
	ns, _, err := seal.ParseKid(kid)
	if err != nil {
		return nil
	}
	kr, err := seal.ResourceKey(ke, ns, resource)
	if err != nil {
		return nil
	}
	k.res[kid+"\n"+resource] = kr
	return kr
}

// key returns the key opening content of resource ("" for namespace
// content) sealed under kid, fetching it if needed: first from via's
// /keys, the namespace read, which for a base's content it reads through
// gives the base's keys (Addendum E Levels), and only if that fails from
// the /keys of the namespace the kid names (§F.8.1).
func (k *Keys) key(ctx context.Context, c *Client, kid, resource, via string) ([]byte, error) {
	if b := k.cached(kid, resource); b != nil {
		return b, nil
	}
	if k.noFetch {
		return nil, ErrNoKeys
	}
	kns, epoch, err := seal.ParseKid(kid)
	if err != nil {
		return nil, err
	}
	err = k.fetch(ctx, c, via, epoch, resource)
	if b := k.cached(kid, resource); b != nil {
		return b, nil
	}
	if kns != via {
		if ferr := k.fetch(ctx, c, kns, epoch, resource); err == nil {
			err = ferr
		}
		if b := k.cached(kid, resource); b != nil {
			return b, nil
		}
	}
	if err != nil {
		return nil, err
	}
	return nil, ErrNoKeys
}

// fetch caches the keys of epoch (for resource, if set) that ns's /keys
// gives.
func (k *Keys) fetch(ctx context.Context, c *Client, ns string, epoch int, resource string) error {
	var res []string
	if resource != "" {
		res = []string{resource}
	}
	got, err := c.FetchKeys(ctx, ns, []int{epoch}, res)
	if err != nil {
		return err
	}
	for _, e := range got {
		if e.From != "" {
			// A keyring entry an e2e namespace relays (§E.3.2): E2E opens
			// those, with the senders it knows.
			continue
		}
		key := e.Key
		if key == nil {
			if k.recipient == nil {
				return fmt.Errorf("client: keys are wrapped to the grant's enc; NewKeys needs the recipient private key")
			}
			if key, err = seal.UnwrapKey(k.recipient, e.Wrapped); err != nil {
				return fmt.Errorf("client: unwrapping %s: %w", e.Kid, err)
			}
		}
		if e.Resource == "" {
			k.Add(e.Kid, key)
		} else {
			k.AddResource(e.Kid, e.Resource, key)
		}
	}
	return nil
}

// WithKeys decrypts sealed namespaces with keys from k (Addendum E.2).
func WithKeys(k *Keys) Option { return func(c *Client) { c.keys = k } }

// KeyEntry is one key of a POST /ns/{ns}/keys answer (§E.2.3): Key is set
// for a raw key, Wrapped for one wrapped to the grant's enc.
type KeyEntry struct {
	Kid      string
	Resource string // the answer's name: set for a per-resource key K_r
	// From is set for a keyring entry an e2e namespace relays (§E.3.2):
	// the thumbprint of the admin key that wrapped it in HPKE auth mode.
	From    string
	Key     []byte
	Wrapped seal.WrappedKey
}

// KeysAnswer is a POST /ns/{ns}/keys answer (§E.2.3): the keys, and the
// namespace's current epoch, level ("sealed" or "e2e") and pad, which a
// writer limited to some resources needs to seal (§E.3.1) and can't read
// in the namespace document (§C.5).
type KeysAnswer struct {
	Keys  []KeyEntry
	Epoch int
	Level string
	Pad   bool
}

// FetchKeys calls POST /ns/{ns}/keys (§E.2.3). epochs nil asks for every
// epoch the grant may have; resources are for per-resource grants.
func (c *Client) FetchKeys(ctx context.Context, ns string, epochs []int, resources []string) ([]KeyEntry, error) {
	a, err := c.FetchKeysAnswer(ctx, ns, epochs, resources)
	if err != nil {
		return nil, err
	}
	return a.Keys, nil
}

// FetchKeysAnswer is FetchKeys with the whole answer. Empty epochs ask for
// no keys, only the epoch, level and pad. A namespace that isn't sealed is
// 404 not_offered (IsNotOffered): there is nothing to seal.
func (c *Client) FetchKeysAnswer(ctx context.Context, ns string, epochs []int, resources []string) (*KeysAnswer, error) {
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	body := map[string]any{}
	if epochs != nil {
		body["epochs"] = epochs
	}
	if resources != nil {
		body["resources"] = resources
	}
	b, err := encodeJSON(body)
	if err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "POST", "/ns/"+ns+"/keys", nil, &request{body: b, ct: "application/json"})
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	obj := r.obj()
	out := &KeysAnswer{Level: str(obj, "level")}
	if f, ok := obj["epoch"].(float64); ok {
		out.Epoch = int(f)
	}
	out.Pad, _ = obj["pad"].(bool)
	arr, _ := obj["keys"].([]any)
	for _, x := range arr {
		m, _ := x.(map[string]any)
		// A K_r's resource is "name"; servers before v0.63 said "resource".
		e := KeyEntry{Kid: str(m, "kid"), Resource: str(m, "name")}
		if e.Resource == "" {
			e.Resource = str(m, "resource")
		}
		if ks, ok := m["key"].(string); ok {
			if e.Key, err = base64.RawURLEncoding.DecodeString(ks); err != nil || len(e.Key) != seal.KeySize {
				return nil, fmt.Errorf("client: %s: malformed key", e.Kid)
			}
		} else if e.Wrapped, err = seal.ParseWrappedKey(m); err != nil {
			return nil, fmt.Errorf("client: %s: %w", e.Kid, err)
		} else if e.Wrapped.Kid != e.Kid || e.Wrapped.Resource != e.Resource {
			return nil, fmt.Errorf("client: %s: wrapped key mismatch", e.Kid)
		}
		e.From = e.Wrapped.From
		out.Keys = append(out.Keys, e)
	}
	return out, nil
}

// Sealed reports whether namespace ns is sealed (Addendum E.2): its
// namespace document is served as a JWE. It needs read access.
func (c *Client) Sealed(ctx context.Context, ns string) (bool, error) {
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		return false, err
	}
	r, err := c.do(ctx, "GET", "/ns/"+ns+"/rev/"+h.ID, nil, nil)
	if err != nil {
		return false, err
	}
	if r.status != 200 {
		return false, r.apiError()
	}
	return isJOSE(r), nil
}

func isJOSE(r *response) bool {
	ct := r.header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), seal.ContentType)
}

// open decrypts a JWE of namespace ns. want returns the pl it must carry,
// given its (unauthenticated) header; resource names the resource whose key
// opens it ("" for namespace content). Its kid must name ns, or, for a
// resource document or log entry an e2e namespace reads through from a
// base, that base (readThrough), whose ns its pl then carries too, as
// Levels have readers accept for content from before the base's raise to
// e2e, which the branch serves as the base does (Addendum E Levels, §E.2.2).
func (c *Client) open(ctx context.Context, ns, resource, jwe string, want func(h *seal.Header) (seal.PL, error)) ([]byte, error) {
	if c.keys == nil {
		return nil, ErrNoKeys
	}
	h, err := seal.ParseHeader(jwe)
	if err != nil {
		return nil, fmt.Errorf("client: sealed content: %w", err)
	}
	kns, _, err := seal.ParseKid(h.Kid)
	if err != nil {
		return nil, fmt.Errorf("client: sealed content: %w", err)
	}
	pl, err := want(h)
	if err != nil {
		return nil, err
	}
	if kns != ns {
		kind, _ := pl["kind"].(string)
		content := resource != "" && (kind == seal.KindDoc || kind == seal.KindRev || kind == seal.KindTombstone)
		through := false
		if content {
			if through, err = c.readThrough(ctx, ns, kns); err != nil {
				return nil, fmt.Errorf("client: reading the bases of %s: %w", ns, err)
			}
		}
		if !through {
			return nil, fmt.Errorf("client: sealed content of %s is sealed under %s: %w", ns, h.Kid, seal.ErrMismatch)
		}
		pl = withNS(pl, kns)
	}
	key, err := c.keys.key(ctx, c, h.Kid, resource, ns)
	if err != nil {
		return nil, err
	}
	return seal.OpenExpect(jwe, key, h.Kid, pl)
}

// withNS is pl with its ns replaced by ns.
func withNS(pl seal.PL, ns string) seal.PL {
	out := make(seal.PL, len(pl))
	for k, v := range pl {
		out[k] = v
	}
	out["ns"] = ns
	return out
}

// readThrough reports whether kns is a base of ns that ns, an e2e
// namespace, reads content through from (Addendum E Levels, Branches of a
// raised base): its base, that base's own bases as far as their documents
// are readable, or for a remote branch the namespaces of its base.chain
// (§G.3). Only e2e namespaces serve a base's sealing so; a sealed branch
// seals what it reads through under its own keys (§E.2.5). Namespace
// documents stay plaintext at E3, so a branch's base chain reads from them.
// Only a chain read without a transient failure is cached.
func (c *Client) readThrough(ctx context.Context, ns, kns string) (bool, error) {
	key := c.BaseURL() + " " + ns
	k := c.keys
	k.mu.Lock()
	bases, ok := k.bases[key]
	k.mu.Unlock()
	if !ok {
		var err error
		if bases, err = c.readThroughBases(ctx, ns); err != nil {
			return false, err
		}
		k.mu.Lock()
		if k.bases == nil {
			k.bases = map[string]map[string]bool{}
		}
		k.bases[key] = bases
		k.mu.Unlock()
	}
	return bases[kns], nil
}

// readThroughBases lists the bases ns reads through, nil if ns isn't an e2e
// branch or its document can't be read (readThrough). A transport error, or
// an answer that may change on retry (429, 5xx), is an error: the chain is
// then unknown, not empty.
func (c *Client) readThroughBases(ctx context.Context, ns string) (map[string]bool, error) {
	var out map[string]bool
	for cur, e2e := ns, true; cur != "" && !out[cur]; {
		h, err := c.NSHead(ctx, cur)
		if err != nil {
			return out, transient(err)
		}
		r, err := c.do(ctx, "GET", "/ns/"+cur+"/rev/"+h.ID, nil, nil)
		if err != nil {
			return out, err
		}
		if r.status != 200 {
			return out, transient(r.apiError())
		}
		if isJOSE(r) {
			return out, nil
		}
		doc, _ := r.value().(map[string]any)
		if e2e {
			// ns itself must be end-to-end.
			enc, _ := doc["encryption"].(map[string]any)
			if lv, _ := enc["level"].(string); lv != "e2e" {
				return nil, nil
			}
			e2e = false
		}
		b, _ := doc["base"].(map[string]any)
		next, _ := b["ns"].(string)
		if next == "" {
			return out, nil
		}
		if out == nil {
			out = map[string]bool{}
		}
		if _, remote := b["origin"]; remote {
			out[next] = true
			chain, _ := b["chain"].([]any)
			for _, x := range chain {
				if s, ok := x.(string); ok && ValidNSName(s) {
					out[s] = true
				}
			}
			return out, nil
		}
		out[next] = true
		cur = next
	}
	return out, nil
}

// transient is err if retrying may give another answer (a transport error,
// 429 or 5xx), else nil: a document the reader can't read ends the chain.
func transient(err error) error {
	var ae *APIError
	if errors.As(err, &ae) && ae.Status != 429 && ae.Status < 500 {
		return nil
	}
	return err
}

func fixedPL(pl seal.PL) func(*seal.Header) (seal.PL, error) {
	return func(*seal.Header) (seal.PL, error) { return pl, nil }
}

// entryPL accepts a resource log entry's pl for any id, of kind rev or
// tombstone; the decrypted entry must then match it.
func entryPL(ns, name string) func(*seal.Header) (seal.PL, error) {
	return func(h *seal.Header) (seal.PL, error) {
		id, _ := h.PL["id"].(string)
		kind, _ := h.PL["kind"].(string)
		if kind != seal.KindRev && kind != seal.KindTombstone {
			return nil, fmt.Errorf("client: sealed log entry of kind %q: %w", kind, seal.ErrMismatch)
		}
		return seal.ResourcePL(ns, name, id, kind), nil
	}
}

// openEntry decrypts one sealed resource log entry and checks it against
// its pl.
func (c *Client) openEntry(ctx context.Context, ns, name, jwe string) (LogEntry, error) {
	h, _ := seal.ParseHeader(jwe)
	pt, err := c.open(ctx, ns, name, jwe, entryPL(ns, name))
	if err != nil {
		return LogEntry{}, err
	}
	v, err := jsonv.Parse(pt)
	if err != nil {
		return LogEntry{}, fmt.Errorf("client: sealed log entry: %w", err)
	}
	e, err := parseLogEntry(v)
	if err != nil {
		return LogEntry{}, err
	}
	if e.ID != h.PL["id"] || e.Kind != h.PL["kind"] {
		return LogEntry{}, fmt.Errorf("client: sealed log entry %s does not match its binding: %w", e.ID, seal.ErrMismatch)
	}
	e.Kid = h.Kid
	return e, nil
}

// openLog decodes a resource log response: plain entries, or in a sealed
// namespace an array of per-entry JWEs, which must chain from since and end
// at last (when not "").
func (c *Client) openLog(ctx context.Context, ns, name, since, last string, r *response) ([]LogEntry, error) {
	arr, ok := r.value().([]any)
	if !ok {
		return nil, fmt.Errorf("client: %s: log is not an array", r.path)
	}
	if len(arr) == 0 {
		return []LogEntry{}, nil
	}
	if _, sealed := arr[0].(string); !sealed {
		return parseLog(r)
	}
	out := make([]LogEntry, 0, len(arr))
	prev := since
	for i, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("client: %s: mixed sealed log", r.path)
		}
		e, err := c.openEntry(ctx, ns, name, s)
		if err != nil {
			return nil, err
		}
		if (i > 0 || since != "") && e.Parent != prev {
			return nil, fmt.Errorf("client: sealed log of %s/%s does not chain at %s: %w", ns, name, e.ID, seal.ErrMismatch)
		}
		prev = e.ID
		out = append(out, e)
	}
	if last != "" && prev != last {
		return nil, fmt.Errorf("client: sealed log of %s/%s ends at %s, not %s: %w", ns, name, prev, last, seal.ErrMismatch)
	}
	return out, nil
}

// openRange decrypts a sealed namespace log range (since, to].
func (c *Client) openRange(ctx context.Context, ns, since, to, jwe string) (any, error) {
	pt, err := c.open(ctx, ns, "", jwe, fixedPL(seal.RangePL(ns, since, to)))
	if err != nil {
		return nil, err
	}
	return jsonv.Parse(pt)
}
