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

// ErrKeyFetch wraps a failure to fetch keys from POST /ns/{ns}/keys: the
// request failed, or /keys answered an error, which the wrapped error
// gives (an *APIError for an answer, AsAPIError). Whether the keys are
// lacking for good (a 4xx other than 408 and 429, §A.4, §E.2.6) or can't be had
// for now (503 behind, §12.1) is the wrapped error's to tell.
var ErrKeyFetch = errors.New("client: fetching keys failed")

// Keys caches the keys of sealed namespaces and fetches missing ones with
// POST /ns/{ns}/keys. It is safe for concurrent use and may be shared by
// clients with the same grant.
type Keys struct {
	mu        sync.Mutex
	recipient *ecdh.PrivateKey
	epoch     map[string][]byte // kid -> K_e
	nsKeys    map[string][]byte // kid -> K_n, derived from K_e
	res       map[string][]byte // kid "\n" resource -> K_r
	// sub holds the keys below K_r (§E.2.1, v0.89): kid "\n" resource
	// "\n" kind "\n" id -> K_rev ("rev"), K_log ("log") or K_blob
	// ("blob"), derived from K_r or carried by a filtered answer.
	sub map[string][]byte
	// view holds K_view: kid "\n" view -> K_view, from /keys, or derived
	// from K_e.
	view    map[string][]byte
	noView  map[string]bool // kid "\n" view: /keys gave none
	noFetch bool
}

// NewKeys returns an empty key cache. recipient, if not nil, unwraps keys
// the server wraps to the grant's enc (§E.2.3).
func NewKeys(recipient *ecdh.PrivateKey) *Keys {
	return &Keys{recipient: recipient, epoch: map[string][]byte{}, nsKeys: map[string][]byte{}, res: map[string][]byte{},
		sub: map[string][]byte{}, view: map[string][]byte{}, noView: map[string]bool{}}
}

// Kinds of the keys below K_r (subKey).
const (
	subRev  = "rev"
	subLog  = "log"
	subBlob = "blob"
)

// AddView caches a view key K_view of view (§E.2.1), as /keys gives a
// partial reader (§E.2.3).
func (k *Keys) AddView(kid, view string, key []byte) {
	k.mu.Lock()
	k.view[kid+"\n"+view] = append([]byte(nil), key...)
	k.mu.Unlock()
}

// addSub caches a key below K_r of resource, kind subRev, subLog or
// subBlob, for id (a revision's or a blob's).
func (k *Keys) addSub(kid, resource, kind, id string, key []byte) {
	k.mu.Lock()
	k.sub[kid+"\n"+resource+"\n"+kind+"\n"+id] = append([]byte(nil), key...)
	k.mu.Unlock()
}

// cachedSub returns a cached key below K_r, or one derived from a K_r or
// K_e cached, nil if neither is.
func (k *Keys) cachedSub(kid, resource, kind, id string) []byte {
	k.mu.Lock()
	b := k.sub[kid+"\n"+resource+"\n"+kind+"\n"+id]
	k.mu.Unlock()
	if b != nil {
		return b
	}
	kr := k.cached(kid, resource)
	if kr == nil {
		return nil
	}
	return deriveSub(kr, kind, id)
}

// deriveSub derives K_rev, K_log or K_blob of id from K_r (§E.2.1).
func deriveSub(kr []byte, kind, id string) []byte {
	var b []byte
	var err error
	switch kind {
	case subRev:
		b, err = seal.RevKey(kr, id)
	case subLog:
		b, err = seal.LogKey(kr, id)
	case subBlob:
		b, err = seal.BlobKey(kr, id)
	default:
		return nil
	}
	if err != nil {
		return nil
	}
	return b
}

// cachedView returns K_view of view for kid: cached, or derived from a
// cached K_e, which derives every K_view (§E.2.1); nil otherwise.
func (k *Keys) cachedView(kid, view string) []byte {
	k.mu.Lock()
	b, ke := k.view[kid+"\n"+view], k.epoch[kid]
	k.mu.Unlock()
	if b != nil || ke == nil {
		return b
	}
	ns, _, err := seal.ParseKid(kid)
	if err != nil {
		return nil
	}
	b, err = seal.FilterViewKey(ke, ns, view)
	if err != nil {
		return nil
	}
	return b
}

// subKey returns the key below K_r of resource that content sealed under
// kid opens with (kind subRev, subLog or subBlob, for id): carried by a
// filtered answer, or derived from K_r, fetched as key fetches it.
func (k *Keys) subKey(ctx context.Context, c *Client, kid, resource, kind, id, via string) ([]byte, error) {
	if b := k.cachedSub(kid, resource, kind, id); b != nil {
		return b, nil
	}
	kr, err := k.key(ctx, c, kid, resource, via)
	if err != nil {
		return nil, err
	}
	if b := deriveSub(kr, kind, id); b != nil {
		return b, nil
	}
	return nil, ErrNoKeys
}

// gaveView reports whether /keys gave K_view of view for kid (AddView), as
// against one derived from a K_e.
func (k *Keys) gaveView(kid, view string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.view[kid+"\n"+view] != nil
}

// viewKey returns K_view of view for kid, fetching keys from via's /keys
// if needed (§E.2.3).
func (k *Keys) viewKey(ctx context.Context, c *Client, kid, view, via string) ([]byte, error) {
	if b := k.cachedView(kid, view); b != nil {
		return b, nil
	}
	k.mu.Lock()
	lacking := k.noView[kid+"\n"+view]
	k.mu.Unlock()
	if k.noFetch || lacking {
		return nil, ErrNoKeys
	}
	_, epoch, err := seal.ParseKid(kid)
	if err != nil {
		return nil, err
	}
	if err := k.fetch(ctx, c, via, epoch, ""); err != nil {
		return nil, err
	}
	if b := k.cachedView(kid, view); b != nil {
		return b, nil
	}
	// Outside the grant's window (§E.2.3): remembered, so that keys of
	// older epochs in later answers don't ask /keys again, each drawing
	// a token of exchangeRate (§6.6).
	k.mu.Lock()
	k.noView[kid+"\n"+view] = true
	k.mu.Unlock()
	return nil, ErrNoKeys
}

// StaticKeys returns a key cache that never fetches: only keys added with
// Add and AddResource are used.
func StaticKeys() *Keys {
	k := NewKeys(nil)
	k.noFetch = true
	return k
}

// Add caches an epoch key K_e under its kid "{ns}#{e}". K_e itself opens
// nothing: namespace content (namespace documents, log ranges, events and
// grants) opens under K_n and resource content under K_r, both derived
// from it (§E.2.1).
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
	if resource == "" {
		if kn, ok := k.nsKeys[kid]; ok {
			return kn
		}
	}
	ke, ok := k.epoch[kid]
	if !ok {
		return nil
	}
	ns, _, err := seal.ParseKid(kid)
	if err != nil {
		return nil
	}
	if resource == "" {
		// K_n = HKDF(K_e, "patchlog-e2", ns ‖ 0x0A) (§E.2.1).
		kn, err := seal.NamespaceKey(ke, ns)
		if err != nil {
			return nil
		}
		k.nsKeys[kid] = kn
		return kn
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
		return fmt.Errorf("%w: %s epoch %d: %w", ErrKeyFetch, ns, epoch, err)
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
				// No recipient key opens it: lacking, as no key is
				// (§A.4, §E.2.6), not a failure for now.
				return fmt.Errorf("%w: keys are wrapped to the grant's enc; NewKeys needs the recipient private key", ErrNoKeys)
			}
			if key, err = seal.UnwrapKey(k.recipient, e.Wrapped); err != nil {
				return fmt.Errorf("client: unwrapping %s: %w", e.Kid, err)
			}
		}
		switch {
		case e.View != "":
			k.AddView(e.Kid, e.View, key)
		case e.Resource == "":
			k.Add(e.Kid, key)
		default:
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
	// View is the answer's view: set for a partial reader's view key
	// K_view (§E.2.3, v0.89).
	View string
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
	if out.Level != "" {
		// /keys names the level (§E.2.3): learnt, and a lower one than
		// held is refused before any key is taken (levels.go). An answer
		// without one, as before v0.51, teaches nothing.
		if _, err := c.levels.learn(ns, out.Level); err != nil {
			return nil, fmt.Errorf("%w (POST /ns/%s/keys)", err, ns)
		}
	}
	if f, ok := obj["epoch"].(float64); ok {
		out.Epoch = int(f)
	}
	out.Pad, _ = obj["pad"].(bool)
	arr, _ := obj["keys"].([]any)
	for _, x := range arr {
		m, _ := x.(map[string]any)
		// A K_r's resource is "name"; servers before v0.63 said "resource".
		e := KeyEntry{Kid: str(m, "kid"), Resource: str(m, "name"), View: str(m, "view")}
		if e.Resource == "" {
			e.Resource = str(m, "resource")
		}
		if ks, ok := m["key"].(string); ok {
			if e.Key, err = base64.RawURLEncoding.DecodeString(ks); err != nil || len(e.Key) != seal.KeySize {
				return nil, fmt.Errorf("client: %s: malformed key", e.Kid)
			}
		} else if e.Wrapped, err = seal.ParseWrappedKey(m); err != nil {
			return nil, fmt.Errorf("client: %s: %w", e.Kid, err)
		} else if e.Wrapped.Kid != e.Kid || e.Wrapped.Resource != e.Resource || e.Wrapped.View != e.View {
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
	if _, err := c.learnDocLevel(ns, r); err != nil {
		return false, err
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
// opens it ("" for namespace content, under K_n). Its kid must name ns,
// and so must its pl: a payload in the §E.2.2 form is never a base's,
// since a sealed branch seals all it serves under its own keys (§E.2.5)
// and a base's ns is accepted only at E3 (Addendum E Levels, §E.2.2,
// v0.85), where what a branch reads through is sealed patch sets and
// prune snapshots, which the E2E view opens, up to the resource's foreign
// parent (chainCheck).
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
		return nil, fmt.Errorf("client: sealed content of %s is sealed under %s: %w", ns, h.Kid, seal.ErrMismatch)
	}
	// pl is compared with what was fetched before any key is derived from
	// it: a JWE bound to another revision is a mismatch, not a failed
	// decryption under that revision's key.
	if err := h.Expect(h.Kid, pl); err != nil {
		return nil, err
	}
	// A revision's document opens under its K_rev, a log entry under its
	// K_log (§E.2.1, v0.89); other resource content, purge and prune
	// events, under K_r; namespace content under K_n.
	var key []byte
	id, _ := pl["id"].(string)
	switch kind, _ := pl["kind"].(string); {
	case resource != "" && kind == seal.KindDoc && id != "":
		key, err = c.keys.subKey(ctx, c, h.Kid, resource, subRev, id, ns)
	case resource != "" && (kind == seal.KindRev || kind == seal.KindTombstone) && id != "":
		key, err = c.keys.subKey(ctx, c, h.Kid, resource, subLog, id, ns)
	default:
		key, err = c.keys.key(ctx, c, h.Kid, resource, ns)
	}
	if err != nil {
		return nil, err
	}
	return seal.OpenExpect(jwe, key, h.Kid, pl)
}

// openFiltered decrypts a filtered answer of view in sealed namespace ns
// (§7.9 Sealed namespaces, §E.2.2): one JWE under the view's K_view, or,
// to a reader holding K_e (a /ns/{ns} cookie's), K_n, bound to pl, the
// unfiltered form's pl with view added, which want returns given the
// (unauthenticated) header; its plaintext { body, keys }. Each view's keys
// JWE it carries is opened under the K_view of its own epoch, where the
// reader has one (others are skipped: a reader opens those of the epochs
// its window covers), bound to { ns, view, name, id, kind: "keys" }, and
// the K_rev, K_log and K_blob it holds are cached for the revision it
// names. It returns the body.
func (c *Client) openFiltered(ctx context.Context, ns, view, jwe string, want func(h *seal.Header) (seal.PL, error)) (any, error) {
	if c.keys == nil {
		return nil, ErrNoKeys
	}
	h, err := seal.ParseHeader(jwe)
	if err != nil {
		return nil, fmt.Errorf("client: filtered answer: %w", err)
	}
	kns, _, err := seal.ParseKid(h.Kid)
	if err != nil {
		return nil, fmt.Errorf("client: filtered answer: %w", err)
	}
	if kns != ns {
		return nil, fmt.Errorf("client: filtered answer of %s sealed under %s: %w", ns, h.Kid, seal.ErrMismatch)
	}
	pl, err := want(h)
	if err != nil {
		return nil, err
	}
	urlView := view != ""
	if !urlView {
		view, _ = h.PL["view"].(string)
	}
	pl = seal.WithView(pl, view)
	if err := h.Expect(h.Kid, pl); err != nil {
		return nil, fmt.Errorf("client: filtered answer: %w", err)
	}
	vk, err := c.keys.viewKey(ctx, c, h.Kid, view, ns)
	if err != nil {
		return nil, err
	}
	if !urlView && !c.keys.gaveView(h.Kid, view) {
		// Where the URL names no view, as at a resource's URLs, pl.view
		// is compared with the view of the key /keys gave the grant the
		// request carried: another view's answer is refused, even one
		// that opens (§E.2.2 Protected header, v0.90).
		return nil, fmt.Errorf("client: filtered answer of view %s, not the one /keys gave the grant: %w", view, seal.ErrMismatch)
	}
	pt, err := seal.OpenExpect(jwe, vk, h.Kid, pl)
	if errors.Is(err, seal.ErrDecrypt) {
		// A /ns/{ns} cookie's answers are under K_n (§7.9).
		if kn := c.keys.cached(h.Kid, ""); kn != nil && c.keys.cachedView(h.Kid, view) != nil {
			pt, err = seal.OpenExpect(jwe, kn, h.Kid, pl)
		}
	}
	if err != nil {
		return nil, err
	}
	body, keys, err := seal.ParseFiltered(pt)
	if err != nil {
		return nil, err
	}
	for _, kj := range keys {
		if err := c.takeViewKeys(ctx, ns, view, kj); err != nil {
			return nil, err
		}
	}
	return body, nil
}

// takeViewKeys opens a view's keys for a revision and caches them; a JWE of
// an epoch the reader has no K_view of is skipped (§E.2.2).
func (c *Client) takeViewKeys(ctx context.Context, ns, view, jwe string) error {
	h, err := seal.ParseHeader(jwe)
	if err != nil {
		return fmt.Errorf("client: view keys: %w", err)
	}
	kns, _, err := seal.ParseKid(h.Kid)
	if err != nil || kns != ns {
		return fmt.Errorf("client: view keys of %s sealed under %s: %w", ns, h.Kid, seal.ErrMismatch)
	}
	name, _ := h.PL["name"].(string)
	id, _ := h.PL["id"].(string)
	if name == "" || id == "" {
		return fmt.Errorf("client: view keys: %w", seal.ErrMismatch)
	}
	pl := seal.ViewKeysPL(ns, view, name, id)
	if err := h.Expect(h.Kid, pl); err != nil {
		return fmt.Errorf("client: view keys: %w", err)
	}
	vk, err := c.keys.viewKey(ctx, c, h.Kid, view, ns)
	if err != nil {
		// Outside the reader's window: no key, nothing taken.
		return nil
	}
	pt, err := seal.OpenExpect(jwe, vk, h.Kid, pl)
	if err != nil {
		return fmt.Errorf("client: view keys of %s/%s: %w", name, id, err)
	}
	ks, err := seal.ParseViewKeys(pt)
	if err != nil {
		return err
	}
	c.keys.addSub(h.Kid, name, subRev, id, ks.Key)
	if ks.Log != nil {
		c.keys.addSub(h.Kid, name, subLog, id, ks.Log)
	}
	for bid, b := range ks.Blobs {
		c.keys.addSub(h.Kid, name, subBlob, bid, b)
	}
	return nil
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
	if isJOSE(r) {
		return c.openFilteredLog(ctx, ns, name, since, last, string(r.body))
	}
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

// openFilteredLog decrypts a partial reader's resource log range or
// long-poll answer of ns/name in a sealed namespace (§7.9 Sealed
// namespaces, §E.2.2): one JWE under its view's K_view, pl { ns, view,
// name, range: [since, end] }, end last where the caller knows it, the
// view its own (the key it holds is its view's alone). Its body holds the
// entries §7.9 shows: one shown with patches as its stored JWE under its
// K_log, which the answer's keys carry, any other in the clear, a hidden
// one as { id, parent, kind: "hidden" }. A filtered log isn't
// chain-verifiable (§10).
func (c *Client) openFilteredLog(ctx context.Context, ns, name, since, last, jwe string) ([]LogEntry, error) {
	body, err := c.openFiltered(ctx, ns, "", jwe, func(h *seal.Header) (seal.PL, error) {
		end := last
		if rg, ok := h.PL["range"].([]any); ok && len(rg) == 2 && end == "" {
			end, _ = rg[1].(string)
		}
		return seal.PL{"ns": ns, "name": name, "range": []any{since, end}}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("client: log of %s/%s: %w", ns, name, err)
	}
	arr, ok := body.([]any)
	if !ok {
		return nil, fmt.Errorf("client: log of %s/%s: the filtered body is not an array", ns, name)
	}
	out := make([]LogEntry, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			e, err := c.openEntry(ctx, ns, name, s)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
			continue
		}
		e, err := parseLogEntry(x)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
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

// openNSEvent decrypts a sealed namespace event for the entry with id id
// (§E.2.2, §7.3): under K_n, pl exactly {ns, event: id}.
func (c *Client) openNSEvent(ctx context.Context, ns, id, jwe string) (any, error) {
	pt, err := c.open(ctx, ns, "", jwe, fixedPL(seal.NamespaceEventPL(ns, id)))
	if err != nil {
		return nil, err
	}
	return jsonv.Parse(pt)
}
