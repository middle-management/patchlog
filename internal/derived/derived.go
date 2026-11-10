// Package derived is what the consumer services (the index of Addendum A,
// the tree and catalog services of Addendum B) share for encrypted source
// namespaces (Addendum E): reading them with keys, and sealing the views
// they derive from them (§E.2.5, §E.2.6, §E.3.2).
//
// Reading. A sealed (E2) namespace is read with the service's own grant and
// a client built WithKeys: keys come from POST /ns/{ns}/keys, wrapped (HPKE)
// to the grant's enc when it has one, and unwrapped with the service's
// X25519 private key (NewKeys' recipient). An end-to-end (E3) namespace is
// read only when that key is a recipient of the namespace's keyring:
// documents are folded with client.E2E. Without keys the namespace is
// skipped and the reason reported (Keys.Check, Keys.Status); ciphertext is
// never consumed as content.
//
// Sealing (§E.2.6). Values a view derives from a sealed or e2e namespace's
// content (scores, facets, titles, …) are sealed in the compact JWE format
// of §E.2.2 (alg "dir", enc "A256GCM", kid "{ns}#{e}") under a key derived
// from the epoch the revision they derive from is served under (EpochOf:
// the kid of the sealed document fetched at E2, of the sealed op at E3;
// Keys.KeyAt), the epoch current when the view is produced where that
// isn't known; a whole response only when all its values derive from
// revisions of one epoch. Names, ids, URLs, heads, structure, at, order
// and cursors stay in the clear. view is
// the request target (path and query) of the …/at/{at}/… URL the response
// is served at, as the service's redirect gives it, so the ciphertext is
// bound to one query, subject set and checkpoint:
//
//	whole response (SealView):  pl { "ns", "view" }, sealed under the view
//	                            key of K_n = NamespaceKey(K_e, ns), served
//	                            as Content-Type application/jose
//	one entry (SealItem):       pl { "ns", "name", "view" }, sealed under
//	                            the view key of K_r = ResourceKey(K_e, ns,
//	                            name) of the entry's resource, as
//	                            { …clear, "sealed": "<JWE>" }
//
// A view key is HKDF-SHA256(ikm = K_n or K_r, salt = "patchlog-view", info
// = view) (seal.ViewKey), so views count toward no epoch key's message
// bound (§E.2.1, §E.2.6); a value of another resource nested in an entry
// is sealed as an entry of that resource is (SealItem with its name). The
// view key is derived when a value is sealed, from the Key the caller
// chose, never ahead of it. Entries use the per-resource key, like the
// revisions they derive from (§E.2.1), so a reader holding only some
// per-resource keys opens exactly the entries of those resources. Nothing
// is compressed (a view mixes content of many resources and authors); a
// namespace with encryption.pad pads what is sealed for it to its size
// bucket (§E.2.2).
package derived

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/middle-management/patchlog/internal/seal"
)

// Encryption levels of a namespace document's encryption.level.
const (
	LevelAtRest = "at-rest"
	LevelSealed = "sealed"
	LevelE2E    = "e2e"
)

// Protected reports whether views derived from a namespace at level must
// be sealed: sealed (E2) and e2e (E3). At-rest (E1) changes nothing on the
// wire.
func Protected(level string) bool { return level == LevelSealed || level == LevelE2E }

// View identifies one derived response: what its pl claims bind.
type View struct {
	// NS is the namespace whose epoch key seals the whole response.
	NS string
	// Target is the request target, path and query, of the …/at/{at}/…
	// URL the response is served at.
	Target string
}

// PL is the pl of the whole response: { ns, view }.
func (v View) PL() seal.PL { return seal.PL{"ns": v.NS, "view": v.Target} }

// ItemPL is the pl of one entry derived from resource name of namespace
// ns: { ns, name, view }.
func (v View) ItemPL(ns, name string) seal.PL {
	return seal.PL{"ns": ns, "name": name, "view": v.Target}
}

// Marshal encodes a view body as JSON, as the services write it.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Key is what seals for one namespace under one epoch: the epoch, its
// epoch key and whether the namespace pads (Keys.Current, Keys.KeyAt).
type Key struct {
	NS    string
	Epoch int
	K     []byte // K_e: SealView and SealItem derive K_n or K_r and the view key from it
	Pad   bool
}

func (k Key) seal(key []byte, pl seal.PL, body any) (string, error) {
	b, err := Marshal(body)
	if err != nil {
		return "", err
	}
	if k.Pad {
		return seal.SealPadded(key, seal.Kid(k.NS, k.Epoch), pl, b)
	}
	return seal.SealUncompressed(key, seal.Kid(k.NS, k.Epoch), pl, b)
}

// SealView seals a whole response body under the view key of K_n of k.NS
// (= v.NS): ViewKey(NamespaceKey(K_e, ns), view) (§E.2.6).
func SealView(k Key, v View, body any) (string, error) {
	if k.NS != v.NS {
		return "", fmt.Errorf("derived: view of %s sealed with a key of %s", v.NS, k.NS)
	}
	kv, err := wholeViewKey(k.K, k.NS, v.Target)
	if err != nil {
		return "", err
	}
	return k.seal(kv, v.PL(), body)
}

// SealItem seals the sealed values of one entry, derived from k.NS/name,
// under the view key of that resource's K_r: ViewKey(ResourceKey(K_e, ns,
// name), view) (§E.2.6). A value of another resource an entry carries is
// sealed by SealItem with that resource's Key and name.
func SealItem(k Key, v View, name string, values any) (string, error) {
	kr, err := seal.ResourceKey(k.K, k.NS, name)
	if err != nil {
		return "", err
	}
	kv, err := seal.ViewKey(kr, v.Target)
	if err != nil {
		return "", err
	}
	return k.seal(kv, v.ItemPL(k.NS, name), values)
}

// wholeViewKey is the key a whole response of ns is sealed under:
// ViewKey(NamespaceKey(K_e, ns), view) (§E.2.6).
func wholeViewKey(ke []byte, ns, view string) ([]byte, error) {
	kn, err := seal.NamespaceKey(ke, ns)
	if err != nil {
		return nil, err
	}
	return seal.ViewKey(kn, view)
}

// OpenView decrypts a sealed view: keyOf returns the epoch key K_e of the
// kid the JWE names (nil if the reader has none), from which the view key
// of K_n is derived, and the JWE must be bound to v.
func OpenView(jwe string, keyOf func(kid string) []byte, v View) ([]byte, error) {
	return open(jwe, keyOf, v.NS, v.PL(), func(ke []byte) ([]byte, error) { return wholeViewKey(ke, v.NS, v.Target) })
}

// OpenItem decrypts one sealed entry derived from ns/name: keyOf returns
// K_r of that resource for the kid the JWE names (ItemKey derives it from
// epoch keys), from which the view key is derived.
func OpenItem(jwe string, keyOf func(kid string) []byte, v View, ns, name string) ([]byte, error) {
	return open(jwe, keyOf, ns, v.ItemPL(ns, name), func(kr []byte) ([]byte, error) { return seal.ViewKey(kr, v.Target) })
}

// ItemKey returns a keyOf for OpenItem that derives K_r of ns/name from
// the epoch keys epochKeyOf returns.
func ItemKey(epochKeyOf func(kid string) []byte, ns, name string) func(string) []byte {
	return func(kid string) []byte {
		ke := epochKeyOf(kid)
		if ke == nil {
			return nil
		}
		kr, err := seal.ResourceKey(ke, ns, name)
		if err != nil {
			return nil
		}
		return kr
	}
}

// open opens jwe under view(keyOf(kid)): the view key derived from the K_e
// or K_r the caller holds for the kid it names.
func open(jwe string, keyOf func(string) []byte, ns string, pl seal.PL, view func([]byte) ([]byte, error)) ([]byte, error) {
	h, err := seal.ParseHeader(jwe)
	if err != nil {
		return nil, err
	}
	kns, _, err := seal.ParseKid(h.Kid)
	if err != nil {
		return nil, err
	}
	// pl is compared with the view fetched before any key is derived from
	// it (§E.2.6: readers compare pl with the URL they fetched), so a JWE
	// of another view is ErrMismatch, not a failed decryption.
	if kns != ns || h.Expect(h.Kid, pl) != nil {
		return nil, seal.ErrMismatch
	}
	k := keyOf(h.Kid)
	if k == nil {
		return nil, ErrNoKey
	}
	kv, err := view(k)
	if err != nil {
		return nil, err
	}
	return seal.OpenExpect(jwe, kv, h.Kid, pl)
}

// ErrNoKey reports a sealed view or entry under a kid the caller has no
// key for.
var ErrNoKey = errors.New("derived: no key for the sealed view")

// ParseRecipientKey parses a service's X25519 private key: the 32-byte
// scalar in base64url (padded or not), as in a JWK's d.
func ParseRecipientKey(s string) (*ecdh.PrivateKey, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("derived: the X25519 private key must be 32 bytes in base64url")
	}
	return ecdh.X25519().NewPrivateKey(b)
}

// LoadRecipientKey reads ParseRecipientKey's format from a file.
func LoadRecipientKey(path string) (*ecdh.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRecipientKey(string(b))
}

// EncodeRecipientKey is the inverse of ParseRecipientKey.
func EncodeRecipientKey(k *ecdh.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(k.Bytes())
}
