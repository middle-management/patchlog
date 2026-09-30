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
// content) sealed under kid, fetching it if needed.
func (k *Keys) key(ctx context.Context, c *Client, kid, resource string) ([]byte, error) {
	if b := k.cached(kid, resource); b != nil {
		return b, nil
	}
	if k.noFetch {
		return nil, ErrNoKeys
	}
	ns, epoch, err := seal.ParseKid(kid)
	if err != nil {
		return nil, err
	}
	var res []string
	if resource != "" {
		res = []string{resource}
	}
	got, err := c.FetchKeys(ctx, ns, []int{epoch}, res)
	if err != nil {
		return nil, err
	}
	for _, e := range got {
		key := e.Key
		if key == nil {
			if k.recipient == nil {
				return nil, fmt.Errorf("client: keys are wrapped to the grant's enc; NewKeys needs the recipient private key")
			}
			if key, err = seal.UnwrapKey(k.recipient, e.Wrapped); err != nil {
				return nil, fmt.Errorf("client: unwrapping %s: %w", e.Kid, err)
			}
		}
		if e.Resource == "" {
			k.Add(e.Kid, key)
		} else {
			k.AddResource(e.Kid, e.Resource, key)
		}
	}
	if b := k.cached(kid, resource); b != nil {
		return b, nil
	}
	return nil, ErrNoKeys
}

// WithKeys decrypts sealed namespaces with keys from k (Addendum E.2).
func WithKeys(k *Keys) Option { return func(c *Client) { c.keys = k } }

// KeyEntry is one key of a POST /ns/{ns}/keys answer: Key is set for a raw
// key, Wrapped for one wrapped to the grant's enc.
type KeyEntry struct {
	Kid      string
	Resource string // set for a per-resource key K_r
	Key      []byte
	Wrapped  seal.WrappedKey
}

// FetchKeys calls POST /ns/{ns}/keys (§E.2.3). epochs nil asks for every
// epoch the grant may have; resources are for per-resource grants.
func (c *Client) FetchKeys(ctx context.Context, ns string, epochs []int, resources []string) ([]KeyEntry, error) {
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
	arr, _ := r.obj()["keys"].([]any)
	var out []KeyEntry
	for _, x := range arr {
		m, _ := x.(map[string]any)
		e := KeyEntry{Kid: str(m, "kid"), Resource: str(m, "resource")}
		if ks, ok := m["key"].(string); ok {
			if e.Key, err = base64.RawURLEncoding.DecodeString(ks); err != nil || len(e.Key) != seal.KeySize {
				return nil, fmt.Errorf("client: %s: malformed key", e.Kid)
			}
		} else if e.Wrapped, err = seal.ParseWrappedKey(m); err != nil {
			return nil, fmt.Errorf("client: %s: %w", e.Kid, err)
		} else if e.Wrapped.Kid != e.Kid || e.Wrapped.Resource != e.Resource {
			return nil, fmt.Errorf("client: %s: wrapped key mismatch", e.Kid)
		}
		out = append(out, e)
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
// opens it ("" for namespace content).
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
	if kns != ns {
		return nil, fmt.Errorf("client: sealed content of %s is sealed under %s: %w", ns, h.Kid, seal.ErrMismatch)
	}
	pl, err := want(h)
	if err != nil {
		return nil, err
	}
	key, err := c.keys.key(ctx, c, h.Kid, resource)
	if err != nil {
		return nil, err
	}
	return seal.OpenExpect(jwe, key, h.Kid, pl)
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
